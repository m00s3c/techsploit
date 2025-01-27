#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}[*] Installing Techsploit...${NC}"

# Install required system packages
echo -e "${GREEN}[*] Installing dependencies...${NC}"
sudo apt update
sudo apt install -y python3 python3-pip

# Create directories
echo -e "${GREEN}[*] Creating installation directories...${NC}"
sudo mkdir -p /opt/techsploit
sudo mkdir -p /usr/local/bin

# Copy files
echo -e "${GREEN}[*] Copying program files...${NC}"
sudo cp -r techsploit/* /opt/techsploit/
sudo cp techsploit/main.py /opt/techsploit/techsploit

# Create symlink
echo -e "${GREEN}[*] Creating symlink...${NC}"
sudo ln -sf /opt/techsploit/techsploit /usr/local/bin/techsploit

# Set permissions
echo -e "${GREEN}[*] Setting permissions...${NC}"
sudo chmod +x /opt/techsploit/techsploit
sudo chmod +x /usr/local/bin/techsploit

# Fix line endings
echo -e "${GREEN}[*] Fixing line endings...${NC}"
sudo sed -i 's/\r$//' /opt/techsploit/techsploit
sudo sed -i 's/\r$//' /usr/local/bin/techsploit

# Install Python packages correctly
echo -e "${GREEN}[*] Installing Python packages...${NC}"
pip install "python-Wappalyzer==0.3.1" "requests>=2.28.0" "nvdlib>=0.7.0" --break-system-packages

echo -e "${GREEN}[+] Installation completed!${NC}"
echo -e "${GREEN}[+] Run 'techsploit --help' to get started${NC}"