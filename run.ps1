& "./venv/scripts/activate.ps1";

cmake --build build;
if ($?) {
    python deploy.py;
}

& deactivate;