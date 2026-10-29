key:
	echo "POSTGRES_DB=biovault_db" > .env
	echo "POSTGRES_USER=biovault_user" >> .env
	python3 -c "import base64, secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(24)); print('FILE_ENCRYPTION_KEY=' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())" >> .env

clean:
	rm -f .env