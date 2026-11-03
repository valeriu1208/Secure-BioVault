key:
	@if [ -e .env ] || [ -e secrets/jwt_private.pem ] || [ -e secrets/jwt_public.pem ]; then \
		echo "Refusing to overwrite existing credentials. Back up existing keys and .env before rotating them."; \
		exit 1; \
	fi
	echo "POSTGRES_DB=biovault_db" > .env
	echo "POSTGRES_USER=biovault_user" >> .env
	python3 -c "import base64, secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(24)); print('FILE_ENCRYPTION_KEY=' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())" >> .env
	python3 -c "import base64, secrets; print('FIELD_ENCRYPTION_KEY=' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())" >> .env
	mkdir -p secrets
	openssl genpkey -algorithm Ed25519 -out secrets/jwt_private.pem
	openssl pkey -in secrets/jwt_private.pem -pubout -out secrets/jwt_public.pem
	chmod 600 secrets/jwt_private.pem

clean:
	rm -f .env
	rm -rf ./secrets

fix_password:
	docker compose exec backend python -c 'from getpass import getpass; from pwdlib import PasswordHash; print(PasswordHash.recommended().hash(getpass("Nova contrasenya admin: ")))'
	echo "Write the following:"
	echo "UPDATE credentials c SET password_hash = 'PEGA_EL_HASH' FROM users u WHERE c.user_id = u.user_id AND u.username = 'admin';"
	echo ""	
	docker compose exec db psql -U biovault_user -d biovault_db
