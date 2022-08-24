"""
app.services
~~~~~~~~~~~~

This module contains the services for the application.
"""
import asyncio
import base64
import solders.keypair as solders_keypair  # type: ignore # pylint: disable=E0401
from solana import keypair, publickey, system_program, transaction
from solana.rpc import api, types
from spl.token import instructions
from spl.token._layouts import ACCOUNT_LAYOUT, MINT_LAYOUT

from app.utils import metadata


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
        max_retries: int = 3,
        skip_confirmation: bool = True,
        max_timeout: int = 60,
        target: int = 20,
        finalized: bool = True,
    ) -> types.RPCResponse | None:
        client = api.Client(api_endpoint)
        signers = await self.remove_duplicate(signers)

        for attempt in range(max_retries):
            try:
                result = client.send_transaction(
                    txn, *signers, opts=types.TxOpts(skip_preflight=True)
                )
                signatures = [str(signature) for signature in txn.signatures]

                if not skip_confirmation:
                    await self.await_confirmation(
                        client, signatures, max_timeout, target, finalized
                    )

                return result
            except Exception as err:  # pylint: disable=W0703
                raise Exception(f"Failed attempt {attempt}: {err}") from err


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
        associated_token_account_info: types.RPCResponse,
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

    def __init__(
        self,
        cfg: dict[str, str],
        max_retries: int | None = None,
        max_timeout: int | None = None,
        supply: int | None = None,
    ) -> None:
        self.max_retries = max_retries or self.max_retries
        self.max_timeout = max_timeout or self.max_timeout
        self.supply = supply or 1
        self.public_key = publickey.PublicKey(cfg["public_key"])
        # self.private_key = list(base58.b58decode(cfg["private_key"]))[:32]
        self.private_key = solders_keypair.Keypair().from_base58_string(
            cfg["private_key"]
        )
        self.keypair = keypair.Keypair(self.private_key)
        self.txn_intf = TransactionInterface()
        self.exe_intf = ExecutionInterface()

    def set_test_params(
        self,
        skip_confirmation: bool | None = None,
        target: int | None = None,
        finalized: bool | None = None,
    ):
        self.skip_confirmation = skip_confirmation or True
        self.target = target or 20
        self.finalized = finalized or False

    async def deploy(
        self, api_endpoint: str, name: str, symbol: str, fee: int
    ) -> dict[str, types.RPCResponse | str | None]:
        tx, signers, contract = await self.txn_intf.deploy(
            api_endpoint, self.keypair, name, symbol, fee
        )
        resp = await self.exe_intf.execute(
            api_endpoint,
            tx,
            signers,
            max_retries=self.max_retries,
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
        supply: int,
    ):
        tx, signers = await self.txn_intf.mint(
            api_endpoint,
            self.keypair,
            contract_key,
            destination_key,
            link,
            supply=supply,
        )
        resp = await self.exe_intf.execute(
            api_endpoint,
            tx,
            signers,
            max_retries=self.max_retries,
            skip_confirmation=self.skip_confirmation,
            max_timeout=self.max_timeout,
            target=self.target,
            finalized=self.finalized,
        )

        return {"response": resp}
