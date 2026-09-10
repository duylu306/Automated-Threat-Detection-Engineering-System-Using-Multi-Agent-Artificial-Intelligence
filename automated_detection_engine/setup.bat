@echo off
echo ================================================
echo  Automated Detection Engine - Windows Setup
echo ================================================

REM Check Python version
python --version 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.11+ from python.org
    pause
    exit /b 1
)

REM Check pip
pip --version 2>nul
if errorlevel 1 (
    echo [ERROR] pip not found
    pause
    exit /b 1
)

echo [1/5] Creating virtual environment...
python -m venv venv
call venv\Scripts\activate.bat

echo [2/5] Upgrading pip...
python -m pip install --upgrade pip

echo [3/5] Installing core dependencies (Phase 1)...
pip install python-dotenv pydantic pydantic-settings

REM PDF processing
pip install PyMuPDF pdfplumber

REM IOC extraction
pip install iocextract

REM STIX / MITRE ATT&CK
pip install stix2 mitreattack-python

REM EVTX parsing
pip install python-evtx

REM NER (cần torch - download lớn ~2GB)
echo [NOTE] Installing PyTorch (CPU only - ~500MB)...
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install transformers sentence-transformers

REM YARA
echo [4/5] Installing YARA...
pip install yara-python

REM Sigma validation
pip install pySigma

REM Vector DB (Chroma - nhẹ hơn Qdrant, tốt cho dev)
pip install chromadb

REM FastAPI
pip install fastapi uvicorn[standard] httpx

REM Utilities
pip install ruamel-yaml datasketch

REM LangChain
pip install langchain langchain-openai langchain-anthropic langchain-community langchain-huggingface langgraph

echo [5/5] Creating .env file...
if not exist .env (
    copy .env.example .env
    echo [OK] .env created. Edit it with your API keys.
) else (
    echo [SKIP] .env already exists
)

echo.
echo ================================================
echo  Setup complete!
echo.
echo  Next steps:
echo  1. Edit .env with your OpenAI API key
echo  2. Run: venv\Scripts\activate
echo  3. Test: python src\extraction\ioc_engine.py
echo  4. Test: python src\mapping\attack_mapper.py
echo ================================================
pause
