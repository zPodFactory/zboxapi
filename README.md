# zBoxApi

zPodFactory zBox Api

## Installation

Complete the following steps to set up zBox Api:

1. Install pipx

    ```bash
    # Install and configure pipx
    apt update
    apt install -y pipx
    pipx ensurepath

    # Reload your profile
    source ~/.zshrc
    ```

1. Install zBoxApi:

    ```bash
    pipx install zboxapi
    ```

1. Set up and start zboxapi.service

    ```bash
    cp zboxapi.service /etc/systemd/system
    systemctl daemon-reload
    systemctl enable zboxapi.service
    systemctl start zboxapi.service
    ```
