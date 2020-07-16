{ pkgs ? import <nixpkgs> {} }:

with pkgs;

mkShell {
  buildInputs = [
    pkgs.python3
    pkgs.python3Packages.flask
    pkgs.python3Packages.ipython
    pkgs.python3Packages.pip
  ];
  shellHook = ''
    alias pip3="PIP_PREFIX='$(pwd)/_build/pip_packages' \pip3"
    alias pip=pip3
    export PYTHONPATH="$(pwd)/_build/pip_packages/lib/python3.7/site-packages:$PYTHONPATH"
    unset SOURCE_DATE_EPOCH7

    export FLASK_APP=flaskrer
    export FLASK_ENV=development
  '';
}
