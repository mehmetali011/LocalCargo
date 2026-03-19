#!/bin/bash
set -e

echo "Downloading LocalCargo for linux..."
curl -sSL -o LocalCargo-linux.zip "https://github.com/mehmetali011/LocalCargo/releases/download/v1.0.0/LocalCargo-linux.zip"

echo "Extracting zip..."
unzip -q -o LocalCargo-linux.zip

echo "Installing..."
sudo mv LocalCargo /usr/local/bin/localcargo
sudo chmod +x /usr/local/bin/localcargo

echo "Cleanup..."
rm LocalCargo-linux.zip

echo "✅ Setup completed! type localcargo to run."
