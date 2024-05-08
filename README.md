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

1. Install pyenv and add 3.12.1

    ```bash

    # Install required packages
    apt update
    apt install -y make build-essential libssl-dev zlib1g-dev \
        libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm \
        libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev \
        liblzma-dev

    # Install pyenv
    curl https://pyenv.run | bash

    # Configure user profile
    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
    echo '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
    echo 'eval "$(pyenv init -)"' >> ~/.zshrc

    # Reload your profile
    source ~/.zshrc

    # Install 3.12.1
    pyenv install 3.12.1
    ```

1. Install zBoxApi:

    ```bash
    pipx install zboxapi --python /root/.pyenv/versions/3.12.1/bin/python3
    ```

1. Set up and start zboxapi.service

    ```bash
    cp zboxapi.service /etc/systemd/system
    systemctl daemon-reload
    systemctl enable zboxapi.service
    systemctl start zboxapi.service
    ```
