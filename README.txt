README — Tamenny Setup Guide
============================

FOLDER STRUCTURE
----------------
tamenny/
├── main.py                        ← uvicorn entry point
├── .env                           ← environment variables (fill in your values)
├── requirements.txt
├── app/
│   ├── __init__.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── routers/
│   │   ├── auth.py               ← /api/auth/register  /api/auth/login
│   │   ├── users.py              ← /api/users/me
│   │   ├── emails.py             ← /api/emails/analyze  /api/emails/{id}/pdf
│   │   └── messages.py           ← /api/messages/analyze  (SMS/WhatsApp)
│   ├── services/
│   │   ├── emailParser.py        ← .eml parser (bytes → dict)
│   │   ├── virustotal.py         ← VirusTotal API client
│   │   ├── aggregator.py         ← orchestrates VT scanning
│   │   ├── phishing_detector.py  ← rule-based engine + scoring
│   │   ├── nlp_model.py          ← BERT spam classifier + fine-tune
│   │   └── pdf_report.py         ← ReportLab PDF generator
│   ├── utilities/
│   │   ├── config.py             ← pydantic-settings
│   │   ├── util.py               ← password hashing
│   │   └── oauth2.py             ← JWT creation/verification
│   ├── templates/
│   │   └── index.html            ← full Jinja2 frontend
│   ├── static/                   ← (CSS/JS/images if needed)
│   └── data/
│       ├── flags/
│       ├── parsed/
│       ├── results/
│       └── nlp_model/            ← fine-tuned model saved here


STEP 1 — Prerequisites
-----------------------
1. Python 3.11+
2. PostgreSQL installed and running
3. Tesseract OCR (for image-to-text in EML)

   Windows: https://github.com/UB-Mannheim/tesseract/wiki
   After installing, add it to PATH or set in emailParser.py:
       pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

   Arabic language pack: download ara.traineddata and place in
   C:\Program Files\Tesseract-OCR\tessdata\

4. (Optional) CUDA GPU for faster NLP inference


STEP 2 — Install Python packages
----------------------------------
  pip install -r requirements.txt


STEP 3 — Set up PostgreSQL database
-------------------------------------
  Open psql or pgAdmin and run:
      CREATE DATABASE tamenny_db;

  Then fill in .env:
      DATABASE_USERNAME=postgres
      DATABASE_PASSWORD=yourpassword
      DATABASE_HOSTNAME=localhost
      DATABASE_PORT=5432
      DATABASE_NAME=tamenny_db


STEP 4 — Configure .env
-------------------------
  SECRET_KEY      → any long random string (32+ chars)
  VIRUSTOTAL_API_KEY → get free key at https://www.virustotal.com/gui/join-us


STEP 5 — Run the server
------------------------
  From the tamenny/ folder:
      uvicorn main:app --reload --host 0.0.0.0 --port 8000

  Then open: http://localhost:8000


STEP 6 — Fine-tune NLP model (optional)
-----------------------------------------
  Prepare a CSV with no header:
      "message text",1
      "another message",0
      (1 = spam, 0 = legitimate)

  Run:
      python -m app.services.nlp_model --csv path/to/training.csv --epochs 3

  The fine-tuned model is saved to app/data/nlp_model/
  and automatically loaded on next server restart.


API DOCS
---------
  Swagger UI:  http://localhost:8000/api/docs
  ReDoc:       http://localhost:8000/api/redoc


KEY ENDPOINTS
--------------
  POST /api/auth/register     → create account
  POST /api/auth/login        → get JWT token
  GET  /api/users/me          → current user profile
  POST /api/emails/analyze    → upload .eml → full analysis
  GET  /api/emails/           → list all analyses
  GET  /api/emails/{id}       → single analysis detail
  GET  /api/emails/{id}/pdf   → download PDF report
  DELETE /api/emails/{id}     → delete analysis
  POST /api/messages/analyze  → analyze SMS/WhatsApp/Telegram text
