# noAPIframe
Basic framework for creating REST backends and just focus on businesslogic

## Development Environment Setup

Personally I use the following steps to set up my dev-environment. Abstract the steps to your needs.

```
sudo apt update; sudo apt install -y python3 virtualenv direnv
virtualenv -p /usr/bin/python3 venv
venv/bin/pip install -r requirements.txt
venv/bin/pre-commit install
sed -nr '/direnv hook bash/!p;$aeval "\$(direnv hook bash)"' -i ~/.bashrc
source ~/.bashrc
echo -e "source venv/bin/activate\nunset PS1" > .envrc
direnv allow
```
