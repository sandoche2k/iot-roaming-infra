# Deploy roaming capable LoRa infrastructure

```sh
# Install required collections
ansible-galaxy install -r requirements.yml

# Install required python dependencies
pip install cryptography

# Deploy
ansible-playbook -i inventory.yml --ask-vault-password roaming.yml
```
