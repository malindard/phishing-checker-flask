import requests
import json
import logging
import os
from flask import Flask, jsonify, request
from llm_prompt_builder import build_url_prompt, build_email_prompt
from pathlib import Path
from dotenv import load_dotenv

# Tentukan path ke file .env
dotenv_path = Path(__file__).resolve().parent / '.env'
load_dotenv(dotenv_path=dotenv_path)

# Inisialisasi Flask app
app = Flask(__name__)

# Konfigurasi dari environment variables
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "").strip()
MODEL = os.getenv("LLM_MODEL", "deepseek/deepseek-chat-v3-0324:free")

# Konfigurasi logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Validasi dan logging API Key saat startup
if not OPENROUTER_API_KEY:
    logger.critical("FATAL: OPENROUTER_API_KEY tidak ditemukan. Aplikasi akan berhenti.")
    raise ValueError("OPENROUTER_API_KEY tidak ditemukan. Pastikan variabel lingkungan sudah diatur dengan benar di file .env")
else:
    # Log versi tersamar dari key untuk verifikasi
    masked_key = f"{OPENROUTER_API_KEY[:5]}...{OPENROUTER_API_KEY[-4:]}"
    logger.info(f"OpenRouter API Key loaded successfully. (Key: {masked_key})")

def llm_analyzer():
    try:
        content = request.json.get("context", {})

        if not isinstance(content, dict):
            logger.error("Konten yang dikirim bukan dictionary.")
            return jsonify({"status": "error", "message": "Konten harus berupa dictionary"}), 400

        if not content:
            logger.error("Konten kosong atau tidak dikirim.")
            return jsonify({"status": "error", "message": "Konten kosong atau tidak dikirim"}), 400
        
        # Jika konten masih string JSON, decode ulang
        if isinstance(content, str):
            try:
                content = json.loads(content)
                while isinstance(content, str):  # tangani double encoding
                    content = json.loads(content)
            except json.JSONDecodeError as e:
                logger.error(f"Gagal decode JSON: {e}")
                return jsonify({"status": "error", "message": "Konten tidak valid JSON"}), 400
            
        if not isinstance(content, dict):
            logger.error("Konten yang dikirim bukan dictionary.")
            return jsonify({"status": "error", "message": "Konten harus berupa dictionary"}), 400

        # Generate prompt untuk LLM
        input_type = content.get("input_type", "").lower()
        if input_type == "email":
            prompt = build_email_prompt(content)
        else:
            prompt = build_url_prompt(content)
        
        logger.info(f"Generated prompt for id {id}: {prompt}")

        # Kirim request ke OpenRouter API
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost", # Referer bisa penting untuk beberapa API
                "X-Title": "Phishing LLM Analyzer" # Nama aplikasi
            },
            json={
                "model": MODEL,
                "messages": prompt
            },
            timeout=90 # Tambahkan timeout untuk request yang lama
        )

        if response.status_code != 200:
            logger.error(f"LLM API gagal: {response.status_code} - {response.text}")
            return jsonify({
                "status": "error",
                "message": f"LLM API gagal: {response.status_code}"
                }), response.status_code

        if response.status_code == 429:
            rate_msg = response.json().get("error", {}).get("message", "Rate limit exceeded.")
            return jsonify({
                "status": "error",
                "message": f"Rate limit LLM API tercapai: {rate_msg}"
            }), 429
        
        result = response.json()
        logger.info(f"LLM Response: {json.dumps(result, indent=2)}")

        insight = result.get("choices", [{}])[0].get("message", {}).get("content", "No insight from LLM.")

        return jsonify({
            "status": "success",
            "llm_insight": insight
        })

    except Exception as e:
        logger.error(f"Terjadi kesalahan: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

def llm_home():
    return jsonify({"message": "Flask LLM Server Aktif"}), 200
