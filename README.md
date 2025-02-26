> [!WARNING]
> The Blue Brain Project concluded in December 2024, so development has ceased under the BlueBrain GitHub organization.
> Future development will take place at: https://github.com/openbraininstitute/virtual-lab-api

# Virtual Labs API

This is the repository for the REST api that is used to manage virtual labs and their projects, primarily by the [core-web-app](https://github.com/BlueBrain/core-web-app). 

# Dependencies

Make sure you have the following dependencies installed:

- [python](https://www.python.org/downloads/) (version 3.12)
- [poetry](https://python-poetry.org/docs/#installation) (version >=1.5.1)
- [docker](https://docs.docker.com/engine/install/) - Add the docker group to your user to enable running docker without `sudo`. This can be done by running `sudo usermod -a -G <your username>`
- [jq](https://jqlang.github.io/jq/download/)
- Stripe API key (`STRIPE_SECRET_KEY` test key and `STRIPE_DEVICE_NAME=dev` in `./.env.local`)

# Development

1. Install the dependencies

   ```bash
   poetry install
   ```
2. Start dev environment

   ```bash
   make init
   ```
3. Run db migrations (this also initializes the database)

   ```
   make init-db
   ```

This should start the server on port 8000 (http://127.0.0.1:8000)
The docs will be available at http://127.0.0.1:8000/docs#/

# Retrieving tokens for test users

The token for user `test` (only user right now that can create virtual labs) is already copied to your clipboard when you run `make init`.
Tokens for user `test`, `test-1`, or `test-2` can also be retrieved using the script `get_user_token.sh`.
It echoes the token to the stdout as well as copies it to your clipboard.

```bash
./get_user_token.sh
# Now you will be prompted to enter a username. Valid usernames are `test`, `test-1`, or `test-2`. Example:
Enter username (test, test-1 or test-2)
-rtest-1
Access token:
<access_token>
```

# Accessing local (or test) keycloak UI

Add keycloak as host for address 127.0.0.1 in /etc/host file

```bash
echo "127.0.0.1 keycloak" | sudo tee -a /etc/hosts # This adds a line "127.0.0.1 keycloak" to /etc/hosts 
```

Now navigating to http://localhost:9090 or http://keycloak:9090 should load the keycloak web interface

# Generating db migrations

The version numbers are stored in alembic/versions. Alembic can be used to autogenerate migration scripts based on schema changes like so:

```
poetry run alembic revision --autogenerate -m '<A descriptive message>'
```

Note that these migration scripts *should* be reviewed carefully. Also, not all schema changes can be autogerated. Details about which schema changes need scripts to be written manually are [here](https://alembic.sqlalchemy.org/en/latest/autogenerate.html#what-does-autogenerate-detect-and-what-does-it-not-detect).

Migration can be run like so:

```
poetry run alembic upgrade head
```

To check if migration is needed (same as above, alembic cannot check all schema changes):

```
make check-db-schema
```

# Testing

Tests can be run using the following command:

```
make test
```

### Test Billing endpoints

The following section explains how to test attaching a payment method to a customer using Stripe's Setup Intents. This operation primarily involves frontend interactions to verify and confirm the Setup Intent. Therefore, it's crucial to conduct this part of the API testing manually.

#### Prerequisites:

1. **Stripe CLI:** Installation of Stripe CLI is recommended for facilitating local testing and event simulation. It can be downloaded from the [Stripe CLI documentation page](https://stripe.com/docs/stripe-cli).

#### Steps to Test:

1. **Create a Setup Intent:** Initially, create a Setup Intent to prepare for attaching a payment method to a customer by using `/virtual-labs/{virtual_lab_id}/billing/setup-intent` endpoint.
2. **Confirm the Setup Intent:** Manually pass the Setup Intent ID to the `confirm` method to simulate the user confirming their payment details (in the frontend this op is using `stripe.setupConfirm()`). This action triggers Stripe to attach the specified test payment method to the Setup Intent.

Alternatively, if you prefer not to use Stripe CLI, you can execute a POST request directly to Stripe's API to perform these actions. However, using Stripe CLI provides a more integrated and straightforward testing workflow.

For further details on working with Setup Intents and managing payment methods, refer to the [Stripe API documentation on Setup Intents](https://stripe.com/docs/api/setup_intents).

```sh
stripe setup_intents confirm seti_1PFtBwFjhkSGAqrAUHCvTAAA \
  --payment-method=pm_card_visa
```

# IDE Setup

## VS Code

1. Make sure that VSCode is picking up the right python version. This should look like `~/.cache/pypoetry/virtualenvs/virtual-labs[uuid]...`
2. Recommended extensions:
   - Ruff (extension_id - charliermarsh.ruff)
   - MyPy Type Checker (extension_id: ms-python.mypy-type-checker)

# Contributing

To create an MR and push code to it, you will need to setup git-hooks *only the first time you push code to the repo*.

1. Install git hooks to enable pre-push checks

```
poetry run pre-commit install
```

This will setup a git hook (pre-push) that is configured to run the following checks.

- Formatting (using ruff)
- Linting (using ruff)

# Funding & Acknowledgment
 
The development of this software was supported by funding to the Blue Brain Project, a research center of the École polytechnique fédérale de Lausanne (EPFL), from the Swiss government's ETH Board of the Swiss Federal Institutes of Technology.
 
Copyright © 2024 Blue Brain Project/EPFL