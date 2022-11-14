# pylint: disable=R0913,E1101
"""
app.services
~~~~~~~~~~~~

This module contains services for the application.
"""
import ast
import asyncio
import base64
import datetime
import re
import smtplib
import time
import typing
import uuid
from email.mime import multipart, text

import aiohttp
import aioredis
import base58
import orjson
import pydantic
import pytz
import solders.keypair as solders_keypair  # type: ignore # pylint: disable=E0401
import xxhash
from nacl import exceptions, signing
from solana import keypair, publickey, system_program, transaction
from solana.rpc import api
from solana.rpc import types as rpc_types
from spl.token import instructions
from spl.token._layouts import ACCOUNT_LAYOUT, MINT_LAYOUT

from app import models, types
from app.templates import emails
from app.utils import crypto, metadata, requests

STORAGES = "/storages"
ISSUANCES = "/issuances"
LOGS = "/logs"


class LoggerService:
    """Client implementation for Certinize's log aggregation system, Cerog."""

    endpoint_url: str
    timezone: str
    client: aiohttp.ClientSession

    def __init__(self, endpoint_url: str, timezone: str) -> None:
        self.endpoint_url = endpoint_url
        self.timezone = timezone
        self.client = aiohttp.ClientSession(base_url=self.endpoint_url)

    async def add_log_entry(
        self,
        id: str,
        message: str,
        raw: str,
        level: str,
        source: str = "blockchain-api",
        created_at: str | None = None,
    ) -> None:
        """Log a message to the logger service.

        Args:
            id (str): The id of the log entry which should be a UUIDv4 string.
            message (str): A short message, like a title.
            raw (dict[str, str]): Details pertaining to the log entry.
            level (str): The level of the log entry. One of: "info", "warn", "error".
            source (str, optional): The name of the web service where the log entry
                originated. Defaults to "blockchain-api".
            created_at (str | None): The timestamp of the log entry.
        """
        asyncio.create_task(
            self.client.post(
                LOGS,
                json={
                    "id": id,
                    "created_at": created_at
                    or str(datetime.datetime.now(pytz.timezone(self.timezone))),
                    "message": message,
                    "raw": raw,
                    "level": level,
                    "source": source,
                },
            )
        )


class ExecutionInterface:
    """Solana client that abstracts away common execution processes."""

    async def remove_duplicate(self, signers: list[keypair.Keypair]):
        seen: set[keypair.Keypair] = set()
        return [
            signer for signer in signers if not (signer in seen or seen.add(signer))
        ]

    async def _sleep(self, sleep_time: int, elapsed: int):
        await asyncio.sleep(sleep_time)
        return elapsed + sleep_time

    async def await_confirmation(
        self,
        client: api.Client,
        signatures: list[str] | list[bytes],
        max_timeout: int = 60,
        target: int = 20,
        finalized: bool = True,
    ):
        loop = asyncio.get_running_loop()
        elapsed = 0
        confirmations = 0
        is_finalized = False

        while elapsed < max_timeout:
            elapsed = await self._sleep(1, elapsed)
            response = await loop.run_in_executor(
                None, client.get_signature_statuses, signatures
            )
            result = response.get("result", {})

            # The result key is a non-required key; we have to check for its presence.
            # If result is not present, we assume the transaction is not confirmed and
            # end the current loop.
            if not result:
                continue

            if result["value"][0] is not None:
                confirmations = result["value"][0]["confirmations"]
                is_finalized = result["value"][0]["confirmationStatus"] == "finalized"
            else:
                continue

            if not finalized:
                if confirmations >= target or is_finalized:
                    return f"Took {elapsed} seconds to confirm transaction"
            else:
                return f"Took {elapsed} seconds to confirm transaction"

    async def execute(
        self,
        api_endpoint: str,
        txn: transaction.Transaction,
        signers: list[keypair.Keypair],
        max_attempts: int = 3,
        skip_confirmation: bool = True,
        max_timeout: int = 60,
        target: int = 20,
        finalized: bool = True,
    ) -> rpc_types.RPCResponse | None:
        client = api.Client(api_endpoint)
        # signers = await self.remove_duplicate(signers)

        if max_attempts < 1:
            raise ValueError("Max retries must be greater than 0")

        while max_attempts > 0:
            max_attempts -= 1

            try:
                result = client.send_transaction(
                    txn, *signers, opts=rpc_types.TxOpts(skip_preflight=False)
                )
                signatures = [str(signature) for signature in txn.signatures]

                if not skip_confirmation:
                    await self.await_confirmation(
                        client, signatures, max_timeout, target, finalized
                    )

                return result
            except Exception as err:  # pylint: disable=W0703
                if max_attempts == 0:
                    raise RuntimeError(f"Failed: {err}") from err


class TransactionInterface:
    """Client implementation that abstracts away common transaction processes."""

    async def deploy(
        self,
        api_endpoint: str,
        source_account: keypair.Keypair,
        name: str,
        symbol: str,
        fee: int,
    ):
        loop = asyncio.get_running_loop()
        mint_account = keypair.Keypair()
        txn = transaction.Transaction()
        token_account = metadata.TOKEN_PROGRAM_ID

        min_rent_bal = await loop.run_in_executor(
            None,
            api.Client(api_endpoint).get_minimum_balance_for_rent_exemption,
            MINT_LAYOUT.sizeof(),
        )

        # Generate Mint
        txn = txn.add(
            system_program.create_account(
                system_program.CreateAccountParams(
                    from_pubkey=source_account.public_key,
                    new_account_pubkey=mint_account.public_key,
                    lamports=min_rent_bal.get("result", {}),
                    space=MINT_LAYOUT.sizeof(),
                    program_id=token_account,
                )
            )
        )
        txn = txn.add(
            instructions.initialize_mint(
                instructions.InitializeMintParams(
                    decimals=0,
                    program_id=token_account,
                    mint=mint_account.public_key,
                    mint_authority=source_account.public_key,
                    freeze_authority=source_account.public_key,
                )
            )
        )

        create_metadata_ix = await metadata.create_metadata_instruction(
            data=await metadata.create_metadata_instruction_data(
                name, symbol, fee, [str(source_account.public_key)]
            ),
            update_authority=source_account.public_key,
            mint_key=mint_account.public_key,
            mint_authority_key=source_account.public_key,
            payer=source_account.public_key,
        )
        txn = txn.add(create_metadata_ix)

        return txn, [source_account, mint_account], str(mint_account.public_key)

    async def _mint(
        self,
        client: api.Client,
        mint_account: publickey.PublicKey,
        user_account: publickey.PublicKey,
        txn: transaction.Transaction,
        source_account: keypair.Keypair,
        associated_token_account: publickey.PublicKey,
        associated_token_account_info: rpc_types.RPCResponse,
        asset_url: str,
        supply: int,
    ):
        account_info = associated_token_account_info.get("result", {})["value"]

        if account_info is not None:
            account_state = ACCOUNT_LAYOUT.parse(
                base64.b64decode(account_info["data"][0])
            ).state
        else:
            account_state = 0

        if account_state == 0:
            txn = txn.add(
                await metadata.create_associated_token_account_instruction(
                    associated_token_account=associated_token_account,
                    payer=source_account.public_key,
                    wallet_address=user_account,
                    token_mint_address=mint_account,
                )
            )

        # Mint the NFT to the associated token account.
        txn = txn.add(
            instructions.mint_to(
                instructions.MintToParams(
                    program_id=metadata.TOKEN_PROGRAM_ID,
                    mint=mint_account,
                    dest=associated_token_account,
                    mint_authority=source_account.public_key,
                    amount=1,
                    signers=[source_account.public_key],
                )
            )
        )
        token_metadata = await metadata.get_metadata(client, mint_account)

        if token_metadata == {}:
            raise ValueError("Token metadata not found")

        data = token_metadata["data"]
        update_metadata_data = await metadata.update_metadata_instruction_data(
            data["name"],
            data["symbol"],
            asset_url,
            data["seller_fee_basis_points"],
            data["creators"],
            data["verified"],
            data["share"],
        )
        txn = txn.add(
            await metadata.update_metadata_instruction(
                update_metadata_data,
                source_account.public_key,
                mint_account,
            )
        )
        txn = txn.add(
            await metadata.create_master_edition_instruction(
                mint=mint_account,
                update_authority=source_account.public_key,
                mint_authority=source_account.public_key,
                payer=source_account.public_key,
                supply=supply,
            )
        )

        return txn, [source_account]

    async def mint(
        self,
        api_endpoint: str,
        source_account: keypair.Keypair,
        contract_key: str,
        dest_key: str,
        asset_url: str,
        supply: int = 1,
    ):
        loop = asyncio.get_running_loop()
        client = api.Client(api_endpoint)
        mint_account = publickey.PublicKey(contract_key)
        user_account = publickey.PublicKey(dest_key)
        txn = transaction.Transaction()

        associated_token_account = await loop.run_in_executor(
            None, instructions.get_associated_token_address, user_account, mint_account
        )

        associated_token_account_info = await loop.run_in_executor(
            None, client.get_account_info, associated_token_account
        )

        return await self._mint(
            client=client,
            mint_account=mint_account,
            user_account=user_account,
            txn=txn,
            source_account=source_account,
            associated_token_account=associated_token_account,
            associated_token_account_info=associated_token_account_info,
            asset_url=asset_url,
            supply=supply,
        )


class TokenFlow:
    """Implementation of a custom minting flow."""

    max_retries = 3
    max_timeout = 60
    supply = 1
    skip_confirmation = True
    target = 20
    finalized = False

    def __init__(self, cfg: dict[str, str]) -> None:
        self.public_key = publickey.PublicKey(cfg["public_key"])
        self.private_key = solders_keypair.Keypair().from_base58_string(
            cfg["private_key"]
        )
        self.keypair = keypair.Keypair(self.private_key)
        self.txn_intf = TransactionInterface()
        self.exe_intf = ExecutionInterface()

    async def deploy(
        self, api_endpoint: str, name: str, symbol: str, fee: int = 0
    ) -> dict[str, rpc_types.RPCResponse | str | None]:
        """Create a new NFT token by:

        1. Creating a new account with a randomly generated address (invokes
        CreateAccount from the System Program).

        2. Invoking InitializeMint on the new account.

        3. Initializing the metadata for this account by invoking the CreateMetatdata
        instruction from the Metaplex protocol.

        Args:
            api_endpoint (str): The RPC endpoint to connect the network.
            name (str): Name of the NFT Contract (32 bytes max).
            symbol (str): Symbol of the NFT Contract (10 bytes max).
            fee (int): Seller basis fee (value in 10000 ).

        Returns:
            dict[str, rpc_types.RPCResponse | str | None]: Deploy result.
        """
        txn, signers, contract = await self.txn_intf.deploy(
            api_endpoint, self.keypair, name, symbol, fee
        )
        resp = await self.exe_intf.execute(
            api_endpoint,
            txn,
            signers,
            max_attempts=self.max_retries,
            skip_confirmation=self.skip_confirmation,
            max_timeout=self.max_timeout,
            target=self.target,
            finalized=self.finalized,
        )

        return {"response": resp, "contract": contract}

    async def mint(
        self,
        api_endpoint: str,
        contract_key: str,
        destination_key: str,
        link: str,
        supply: int = 1,
    ):
        txn, signers = await self.txn_intf.mint(
            api_endpoint,
            self.keypair,
            contract_key,
            destination_key,
            link,
            supply=supply,
        )
        resp = await self.exe_intf.execute(
            api_endpoint,
            txn,
            signers,
            max_attempts=self.max_retries,
            skip_confirmation=self.skip_confirmation,
            max_timeout=self.max_timeout,
            target=self.target,
            finalized=self.finalized,
        )

        return {"response": resp}


class StorageService:  # pylint: disable=too-few-public-methods
    """A service for storing data into an immediate database or permanent storage."""

    endpoint_url: str
    headers: dict[str, str]
    session: aiohttp.ClientSession

    def __init__(
        self,
        endpoint_url: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.headers = headers or {"X-API-Key": ""}
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            base_url=self.endpoint_url,
            json_serialize=lambda json_: orjson.dumps(  # pylint: disable=E1101
                json_
            ).decode(),
        )

    async def upload_persistent_object(self, object_: dict[str, tuple[str, bytes]]):
        """Upload e-Certificates to persisten storage (IPFS) or Decentralized Cloud
        Storage (DCS). The response values can be used later to verify if the files
        were uploaded successfully.

        Args:
            object (dict[str, tuple[str, bytes]]): Dict containing file data. Example:
                {"filename.jpeg": ("image/jpeg", b'file data')}

        Raises:
            ConnectionError: If the server failed to receive a valid response from the
                object processor.

        Returns:
            dict[str, str]: Details about the upload.
        """
        form_data = aiohttp.FormData()

        for filename, file_object in object_.items():
            form_data.add_field(
                name="file",
                value=file_object[1],
                content_type=file_object[0],
                filename=filename,
            )

        async with self.session.post(url=STORAGES, data=form_data) as resp:
            if resp.status >= 400:
                raise ConnectionError(
                    f"Failed to upload object to permanent storage. "
                    f"Status code: {resp.status}"
                )

            return await resp.json()


class Emailer:  # pylint: disable=R0903
    """Represents a client that handles email sending."""

    def __init__(
        self, sender_address: str, sender_password: str, smtp_server_url: str
    ) -> None:
        self.sender_address = sender_address
        self.sender_password = sender_password
        self.smtp_session = smtplib.SMTP(smtp_server_url, 587)
        self.smtp_session.starttls()
        self.smtp_session.login(self.sender_address, self.sender_password)

    def _send_message(
        self, message: multipart.MIMEMultipart, receiver_addr: str
    ) -> str | None:
        try:
            text_ = message.as_string()
            self.smtp_session.sendmail(self.sender_address, receiver_addr, text_)
        except smtplib.SMTPException as smtp_err:
            return str(smtp_err)

        return None

    async def alt_send_message(
        self, receiver_address: str, subject: str, content: str
    ) -> str | None:
        """Send an email with a MIME type of multipart/alternative.

        Args:
            receiver_address (str): The email address of the recipient.
            subject (str): The subject of the email.
            content (str): The content of the email.

        Returns:
            str | None: The error message if any.
        """
        message = multipart.MIMEMultipart()
        message["From"] = self.sender_address
        message["To"] = receiver_address
        message["Subject"] = subject

        message.attach(text.MIMEText(content, "html"))

        loop = asyncio.get_running_loop()

        return await loop.run_in_executor(
            None, self._send_message, message, receiver_address
        )


class IssuanceUtil:
    nft_storage_link = "https://{cid}.ipfs.nftstorage.link/{filename}"
    filebase_link = "https://ipfs.filebase.io/ipfs/{cid}"
    solana_api_endpoint = "https://api.mainnet-beta.solana.com"

    def __init__(self, solana_api_endpoint: str) -> None:
        self.solana_api_endpoint = solana_api_endpoint

    @staticmethod
    async def create_img_upload_request(
        request: models.IssuanceRequest,
        token_accounts: types.PubkeyMap,
    ) -> tuple[dict[str, str], dict[str, tuple[str, bytes]]]:
        """Create a request to upload the NFT image to a decentralized cloud storage.

        Args:
            request (models.IssuanceRequest): The issuance request.
            token_accounts (dict[str, dict[str, str]]): The token accounts created for
                each recipient.

        Returns:
            tuple[dict[str, str], dict[str, tuple[str, bytes]]]: Used variables.
        """
        # * We have to store the generated file names (xxh3_64) for later retreival with
        # * their corresponding RecipientMeta.recipient_pubkey as the key. File
        # * names are used to associate recipients to their respective certificates.
        filenames: dict[str, str] = {}
        http_client = aiohttp.ClientSession()
        image_files: dict[str, tuple[str, bytes]] = {}

        # Construct the request body for the upload of e-Certificates to permanent
        # storage.
        for recipient in request.recipient_meta:
            if recipient.recipient_pubkey not in token_accounts:
                continue

            time_ = str(datetime.datetime.now().timestamp())
            filename = f"{xxhash.xxh3_64(time_).hexdigest()}.jpeg"
            filenames[recipient.recipient_pubkey] = filename

            certificate_src = await requests.get_files(
                http_client, recipient.recipient_ecert_url
            )

            # We use JPEG as the content-type, the global default, as the ecert
            # processor service produces jpegs to generate e-Certificates.
            image_files[filename] = ("image/jpeg", certificate_src)

        await http_client.close()

        return (filenames, image_files)

    @staticmethod
    async def create_nft_metadata(
        request: models.IssuanceRequest,
        token_accounts: types.PubkeyMap,
        files: list[dict[str, str]],
        filenames: dict[str, str],
        cid: object,
    ) -> types.NftMetadataTup:
        # * Store the filenames with the wallet addresses as keys so that we don't have
        # * to map them later. The content of this dict will be used to mint
        # * e-Certificates and email the issuer and recipients.
        # Example structure: {
        #   "B7KN...": {
        #     "filename": "filename",
        #     "nft_meta": "https://...",
        #     "transaction_sig": "46Kyz...",
        #   }
        # }
        recipient_ecerts: types.PubkeyMap = {}

        # Use the current year and month as the first part of the certificate's unique
        # identifier. This will be used to name the public data storage (JSON file) that
        # that will help verify e-Certificate legitimacy.
        # yr_mth = datetime.datetime.today().strftime("%Y-%m")

        # nft_meta_coll is a collection of dictionaries containing NFT metadata. They
        # will be converted to JSON and uploaded to a permanent storage.
        nft_metas_coll: list[dict[str, typing.Any]] = []

        for recipient in request.recipient_meta:
            if recipient.recipient_pubkey not in token_accounts:
                continue

            # Although we stored the generated file names earlier for retrieval, we
            # still have to check if they were successfully uploaded. To do so, we
            # simply have to check if file name is in the response. We retrieve the
            # file/ecert name from the response using the recipient_pubkey and
            # construct the ecert URL. This is much safer than matching by index, which
            # might cause recipients to receive incorrect e-Certifiactes.
            ecert_url = ""

            for file in files:
                # A `file` contains the name of the file and its content-type. Example:
                # {"name": "5c630887.jpeg", "type": "image/jpeg"}
                ecert_fname = file.get("name")

                if ecert_fname == filenames.get(recipient.recipient_pubkey):
                    ecert_url = IssuanceUtil.nft_storage_link.format(
                        cid=cid, filename=file["name"]
                    )

                    recipient_ecerts[recipient.recipient_pubkey] = {
                        "filename": ecert_fname,
                        "nft_meta": "",
                        "transaction_sig": "",
                    }
                    break

            # Naturally, if ecert_fname is empty, the file was not uploaded. We skip the
            # current iteration.
            if ecert_url == "":
                continue

            # The certificate ID is composed of two xxh3_64 hashed values. The former
            # part of the certificate ID identifies the data storage that can help
            # verify the legitimacy of the e-Certificate. The latter part is a unique
            # identifier assigned to the e-Certificate.
            # certificate_id = (
            #     f"""{xxhash.xxh3_64(yr_mth).hexdigest()}-"""
            #     f"""{xxhash.xxh3_64(f"{uuid.uuid1()}").hexdigest()}"""
            # )

            # The symbol can be anything, but it must be unique. To create a symbol, we
            # combibe the recipient's initials and the xxhash of the current date and
            # time.
            sym_ = (
                f"-{xxhash.xxh3_64(str(datetime.datetime.today())).hexdigest().upper()}"
            )
            symbol = (
                "".join(
                    [name[0].upper() for name in recipient.recipient_name.split(" ")]
                )
                + sym_
            )

            # We have to generate the nft_meta inside a pydantic model to ensure the
            # key-value pairs conform with Metaplex's standard. NOTE: external_url
            # should be a link that leads to the JSON file containing public information
            # about the issuer.
            nft_meta = dict(
                models.NonFungibleTokenMetadata(
                    name=f"{recipient.recipient_name}'s e-Certificate",
                    symbol=symbol,
                    description=(
                        f"Awarded to {recipient.recipient_name} "
                        f"by {request.issuer_meta.issuer_name}"
                    ),
                    image=pydantic.HttpUrl(url=ecert_url, scheme="https"),
                    external_url=request.issuer_meta.issuer_website,
                    attributes=[
                        {
                            "trait_type": "verification",
                            "value": "https://verification.com",
                        }
                    ],
                )
            )

            nft_metas_coll.append(nft_meta)
            recipient_ecerts[recipient.recipient_pubkey][
                "nft_meta"
            ] = f"""{nft_meta["symbol"]}.json"""

        return (recipient_ecerts, nft_metas_coll)

    @staticmethod
    async def construct_email_body(
        request: models.IssuanceRequest,
        recipient_template: str,
        issuer_template: str,
        failure_reached: dict[str, str | None],
        recipient_ecerts: types.PubkeyMap,
    ) -> tuple[str, dict[str, str]]:
        success_recipients = ""
        failed_recipients = ""
        recipient_emails: dict[str, str] = {}

        for recipient in request.recipient_meta:
            if recipient.recipient_pubkey in failure_reached:
                failed_recipients += (
                    f"<hr>{recipient.recipient_name} | "
                    f"{recipient.recipient_pubkey}<br>"
                    f"{failure_reached[recipient.recipient_pubkey]}<br>"
                )
            else:
                success_recipients += (
                    f"<hr>{recipient.recipient_name} | "
                    f"{recipient.recipient_pubkey}<br>"
                )
                recipient_emails[
                    recipient.recipient_pubkey
                ] = recipient_template.format(
                    issuer=request.issuer_meta.issuer_name,
                    details=recipient_ecerts.get(recipient.recipient_pubkey),
                )

        return (
            issuer_template.format(
                success=success_recipients, failed=failed_recipients
            ),
            recipient_emails,
        )

    @staticmethod
    async def email_involved_parties(
        request: models.IssuanceRequest,
        emailer: Emailer,
        issuer_email: str,
        recipient_emails: dict[str, str],
    ) -> None:
        for recipient in request.recipient_meta:
            if recipient.recipient_pubkey not in recipient_emails:
                continue

            _ = await emailer.alt_send_message(
                recipient.recipient_email,
                "E-Certificate Issuance",
                recipient_emails[recipient.recipient_pubkey],
            )

        await emailer.alt_send_message(
            request.issuer_meta.issuer_email,
            "E-Certificate Issuance",
            issuer_email,
        )

    @staticmethod
    async def upload_ecerts(
        request: models.IssuanceRequest,
        token_accounts: types.PubkeyMap,
        storage_svcs: StorageService,
    ) -> types.FnamesUpload:
        filenames, image_files = await IssuanceUtil.create_img_upload_request(
            request, token_accounts
        )
        uploaded_nft_meta = await storage_svcs.upload_persistent_object(image_files)

        return (filenames, uploaded_nft_meta)

    @staticmethod
    async def upload_nft_metadata(
        nft_metadata: types.NftMetadataTup, storage_svcs: StorageService
    ) -> types.EcertsUploadMeta:
        """Uploads NFT metadata to the storage service.

        Args:
            nft_metadata (app.types.NNftMetadataTup): A tuple of NFT metadata.
            storage_svcs (app.services.storage.StorageService): The storage service.
        """
        recipient_ecerts, nft_metas_coll = nft_metadata
        json_meta: dict[str, tuple[str, bytes]] = {}

        for nft_meta in nft_metas_coll:
            json_meta[f"""{nft_meta["symbol"]}.json"""] = (
                "application/json",
                orjson.dumps(nft_meta),
            )

        uploaded_nft_meta = await storage_svcs.upload_persistent_object(json_meta)

        return (recipient_ecerts, uploaded_nft_meta)

    @staticmethod
    async def log_issuance_result(
        logger: LoggerService,
        reference_id: str,
        completed_steps: list[str],
    ):
        if len(completed_steps) >= 8:
            message = "Successfully fulfilled issuance request."
            level = "info"
        else:
            message = "Failed to fulfill issuance request."
            level = "error"

        await logger.add_log_entry(
            str(reference_id),
            message,
            "\n".join(completed_steps),
            level,
        )

    async def create_token_account(
        self, request: models.IssuanceRequest, completed_steps: list[str]
    ) -> types.CreateTokenResult:
        """Create token accounts and map the recipient public keys to the tokens.

        Tip: Doing this in first allows us to check in advance for any issue, like if
        recipient has insufficient funds to pay for the issuance/mint.

        Args:
            request (models.IssuanceRequest): The issuance request.

        Returns:
            types.CreateTokenResult: The result of the token creation.
        """
        cfg = {
            "public_key": request.issuer_meta.issuer_pubkey,
            "private_key": request.signature,
        }
        txn_intf = TokenFlow(cfg=cfg)

        token_accounts: dict[str, dict[str, rpc_types.RPCResponse | str | None]] = {}

        # On any error with creating an account, we store the recipient wallet addresses
        # where the failure occurred. This may be used to send a refund to the
        # issuer/recipients or prompt the issuer to perform the issuance again.
        insuf_funds_reached: dict[str, str | None] = {}

        for recipient in request.recipient_meta:
            nft_id = str(time.time())

            # NOTE: For some reason, the solana library returns the runtime error
            # detail as a string repr of a dict. Here is an example error msg:
            # Failed attempt 0: {
            #   "code":-32002,
            #   "message":"Transaction simulation failed: Attempt... (truncated)",
            #   "data":{
            #     "accounts":"None",
            #     "err":"AccountNotFound",
            #     "logs":[
            #     ],
            #     "unitsConsumed":0
            #   }
            # }
            try:
                completed_steps.append("1.1. Creating token account.")

                token_account = await txn_intf.deploy(
                    api_endpoint=self.solana_api_endpoint,
                    name=xxhash.xxh32(nft_id).hexdigest(),
                    symbol="-".join(list(xxhash.xxh3_64(nft_id).hexdigest()[:5])),
                )

                completed_steps.append("1.2. Created!")

                token_accounts[recipient.recipient_pubkey] = token_account
            except RuntimeError as err:
                err_dict = re.search(r"\{.*\}", str(err))

                if err_dict is not None:
                    ast.literal_eval(err_dict.group(0))
                    insuf_funds_reached[recipient.recipient_pubkey] = ast.literal_eval(
                        err_dict.group(0)
                    ).get("message")
                else:
                    insuf_funds_reached[recipient.recipient_pubkey] = str(err)

                token_account = {}

        return (token_accounts, insuf_funds_reached, txn_intf, completed_steps)

    async def mint_nft(
        self,
        request: models.IssuanceRequest,
        recipient_ecerts: types.PubkeyMap,
        uploaded_nft_meta: typing.Any,
        token_accounts: types.PubkeyMap,
        txn_intf: TokenFlow,
        failure_reached: dict[str, str | None],
    ) -> types.MintResult:
        for recipient in request.recipient_meta:
            nft_meta_url = ""
            nft_meta = recipient_ecerts[recipient.recipient_pubkey]["nft_meta"]

            # Iterate through the uploaded NFT metadata to find the one that matches
            # the current recipient's assigned NFT metadata.
            for resp in uploaded_nft_meta["response_meta"]:
                if resp["Key"] == nft_meta:
                    nft_meta_url = IssuanceUtil.filebase_link.format(
                        cid=resp["HTTPHeaders"]["x-amz-meta-cid"]
                    )
                    break

            token_account = token_accounts.get(recipient.recipient_pubkey)

            if token_account is not None:
                contract_key = token_account["contract"]
            else:
                contract_key = None

            if isinstance(contract_key, str):
                try:
                    mint_result = await txn_intf.mint(
                        api_endpoint=self.solana_api_endpoint,
                        contract_key=contract_key,
                        destination_key=recipient.recipient_pubkey,
                        link=nft_meta_url,
                    )
                except RuntimeError as exc:
                    # * We have to record the failure and email the details to the
                    # * issuer.
                    failure_reached[recipient.recipient_pubkey] = str(exc)
                    continue

                if (rpc_resp := mint_result["response"]) is not None:
                    recipient_ecerts[recipient.recipient_pubkey][
                        "transaction_sig"
                    ] = dict(rpc_resp)["result"]

        return recipient_ecerts, failure_reached

    async def issue_certificate(
        self,
        request: models.IssuanceRequest,
        storage_svcs: StorageService,
        emailer: Emailer,
        reference_id: uuid.UUID,
        logger: LoggerService,
    ) -> None:
        """Handler service for issuance requests.

        Args:
            request (models.IssuanceRequest): Issuance request object.
            storage_svcs (StorageService): Storage service object.
            emailer (Emailer): Emailer object.
        """
        completed_steps: list[str] = []
        filenames: dict[str, str] = {}

        completed_steps.append("1. Creating token accounts.")

        (
            token_accounts,
            failure_reached,
            txn_intf,
            completed_steps,
        ) = await self.create_token_account(request, completed_steps)

        if token_accounts != {}:
            completed_steps.append("2. Uploading e-Certificates.")

            filenames, uploaded_nft_meta = await IssuanceUtil.upload_ecerts(
                request, token_accounts, storage_svcs
            )

            resp_val = uploaded_nft_meta["response_meta"]["value"]
            cid = resp_val["cid"]
            files: list[dict[str, str]] = resp_val["files"]

            completed_steps.append("3. Creating nft metadata.")
            nft_metadata = await IssuanceUtil.create_nft_metadata(
                request, token_accounts, files, filenames, cid
            )
        else:
            nft_metadata = None

        if isinstance(nft_metadata, tuple):
            completed_steps.append("4. Uploading nft metadata.")

            (
                recipient_ecerts,
                uploaded_nft_meta,
            ) = await IssuanceUtil.upload_nft_metadata(nft_metadata, storage_svcs)

            completed_steps.append("5. Minting NFT.")

            recipient_ecerts, failure_reached = await self.mint_nft(
                request,
                recipient_ecerts,
                uploaded_nft_meta,
                token_accounts,
                txn_intf,
                failure_reached,
            )
        else:
            recipient_ecerts = {}

        completed_steps.append("6. Constructing Email.")

        issuer_email, recipient_emails = await IssuanceUtil.construct_email_body(
            request,
            emails.RECIPIENT_EMAIL_TEMPLATE,
            emails.ISSUER_EMAIL_TEMPLATE,
            failure_reached,
            recipient_ecerts,
        )

        completed_steps.append("7. Emailing involved parties.")

        await IssuanceUtil.email_involved_parties(
            request,
            emailer,
            issuer_email,
            recipient_emails,
        )

        completed_steps.append("8. Done.")

        await IssuanceUtil.log_issuance_result(
            logger,
            str(reference_id),
            completed_steps,
        )


class Redis:

    redis_url: str
    connection: aioredis.Redis

    def __init__(self, redis_url: str) -> None:
        self.redis_url = redis_url

    async def connect(self):
        """Connect to the Redis server."""
        self.connection = await aioredis.from_url(  # type: ignore
            self.redis_url, decode_responses=True
        )

    async def get(self, key: str) -> str:
        """Get a value from the Redis server.

        Args:
            key (str): Key to retrieve.

        Returns:
            str: Value retrieved.
        """
        return await self.connection.get(key)  # type: ignore

    async def set(self, key: str, value: str | bytes) -> None:
        """Set a value in the Redis server.

        Args:
            key (str): Key to set.
            value (str): Value to set.
        """
        await self.connection.set(key, value)  # type: ignore

    async def delete(self, key: str) -> None:
        """Delete a key from the Redis server.

        Args:
            key (str): Key to delete.
        """
        await self.connection.delete(key)  # type: ignore

    async def hset(self, key: str, value: dict[str, str | bytes]) -> typing.Any:
        """Set a value in the Redis server.

        Args:
            key (str): Key to set.
            field (str): Field to set.
            value (str): Value to set.
        """
        return await self.connection.hset(  # type:ignore
            key, mapping=value
        )

    async def hgetall(self, key: str) -> dict[str, str | bytes]:
        """Get a value from the Redis server.

        Args:
            key (str): Key to retrieve.

        Returns:
            str: Value retrieved.
        """
        return await self.connection.hgetall(key)  # type: ignore


class TransactionUtil:
    """Utility class for transaction related operations."""

    @staticmethod
    async def generate_message(redis: Redis, keypair: models.Keypair):
        """Create a message to be signed by the user from the client."""
        request_id = str(uuid.uuid1())
        message = (
            "Please sign this message to prove your ownership of the Solana wallet "
            f"address. Your request ID: {request_id}"
        )

        await redis.hset(
            request_id,
            {
                "message": f"{message}",
                "pubkey": keypair.pubkey,
                "pvtkey": keypair.pvtkey,
            },
        )

        return message, request_id

    @staticmethod
    async def verify_signature(
        public_key: str,
        message: str,
        signature: str,
    ) -> bytes:
        """Verify that the signed message is valid.

        Args:
            public_key (str): Solana public key.
            message (str): The message that was signed.
            signature (str): Signature from the signed message.

        Returns:
            bytes: The decoded signature.

        Raises:
            ValueError: If the signature is invalid.
        """
        pubkey = bytes(publickey.PublicKey(public_key))
        msg = bytes(message, "utf-8")
        sig = bytes(signature, "utf-8")

        try:
            return signing.VerifyKey(pubkey).verify(msg, base58.b58decode(sig))
        except exceptions.BadSignatureError as bad_sig:
            raise ValueError(f"Invalid signature: {str(bad_sig)}") from bad_sig
