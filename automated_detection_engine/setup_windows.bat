@echo off
echo === Automated Detection Engine - Windows Setup ===

:: 1. Kiem tra Python
python --version 2>nul || (echo Python chua duoc cai. Download tai python.org && pause && exit)

:: 2. Tao virtual environment
python -m venv .venv
call .venv\Scripts\activate

:: 3. Upgrade pip
python -m pip install --upgrade pip

:: 4. Cai PyTorch CPU (nhe hon, du cho Phase 1)
pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu

:: 5. Cai dependencies chinh
pip install langchain langchain-openai langchain-anthropic langchain-community langchain-huggingface
pip install openai anthropic
pip install chromadb qdrant-client
pip install sentence-transformers transformers
pip install pydantic pydantic-settings python-dotenv

:: 6. Security packages
pip install sigma-cli pySigma yara-python mitreattack-python stix2 iocextract

:: 7. File processing
pip install PyMuPDF pdfplumber python-evtx beautifulsoup4 requests

:: 8. NER (GLiNER)
pip install spacy gliner
python -m spacy download en_core_web_sm

:: 9. Data tools
pip install datasketch PyYAML httpx

:: 10. Backend
pip install fastapi "uvicorn[standard]" sqlalchemy alembic

:: 11. Dev tools
pip install pytest pytest-asyncio black ruff rich

:: 12. Copy env file
copy .env.example .env
echo.
echo === Setup xong! ===
echo Buoc tiep theo:
echo 1. Mo file .env va dien OPENAI_API_KEY
echo 2. Chay: python -m pytest tests/ -v
pause
