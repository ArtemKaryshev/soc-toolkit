@echo off
rem Запуск SOC Toolkit на Windows: первый запуск создаёт окружение и ставит зависимости.
chcp 65001 >nul
cd /d "%~dp0"
if not exist .venv (
    echo Создаю виртуальное окружение...
    py -3 -m venv .venv || python -m venv .venv || goto :nopython
    call .venv\Scripts\activate.bat
    python -m pip install --upgrade pip
    pip install -e . || goto :fail
) else (
    call .venv\Scripts\activate.bat
)
soc-toolkit ui
goto :eof

:nopython
echo Не найден Python 3.11+. Установите его с https://www.python.org/downloads/ (галочка "Add to PATH").
pause
goto :eof

:fail
echo Не удалось установить зависимости. Проверьте интернет или прокси (переменные HTTPS_PROXY).
pause
