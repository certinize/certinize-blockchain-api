RECIPIENT_EMAIL_TEMPLATE = """
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Certificate Issuance</title>
        <style type="text/css">
            .container {{}}
        </style>
    </head>
    <body>
        <p>Congratulations! You received an e-Certificate from {issuer}.</p>
        <p>Check your Solana wallet!</p>
        <p>Details:</p>
        <p>{details}</p>
    </body>
</html>
"""

ISSUER_EMAIL_TEMPLATE = """
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Certificate Issuance</title>
        <style type="text/css">
            .container {{}}
        </style>
    </head>

    <body>
        <div>
            <h3>
                Success
            </h3>
            <div>
                {success}
            </div>
            <hr>
            <h3>
                Failed
            </h3>
            <div>
                {failed}
            </div>
            <hr>
        </div>
    </body>
</html>
"""
