from typing import List, Dict, Any

def build_url_prompt(data: Dict[str, Any]) -> List[Dict[str, str]]:
    def limit_text(arr, max_len=400):
        if not isinstance(arr, list):
            return ""
        joined = "\n".join(arr)
        return (joined[:max_len] + '...') if len(joined) > max_len else joined

    titles = limit_text(data.get("titles", []), max_len=200)
    heads = limit_text(data.get("heads", []), max_len=500)
    forms = limit_text(data.get("forms", []), max_len=500)
    scripts = limit_text(data.get("scripts", []), max_len=500)
    prediction = data.get("prediction", "tidak tersedia").upper()
    confidence = round(data.get("confidence", 0) * 100, 2)
    adjusted = round(data.get("adjusted_confidence", 0) * 100, 2)
    final_prediction = data.get("final_prediction", "tidak tersedia").upper()
    trusted = data.get("trusted_domain", False)
    trusted_str = "YA" if trusted else "TIDAK"

    full_content = (
        f"Judul Halaman (Title):\n{titles}\n\n"
        f"Bagian Head:\n{heads}\n\n"
        f"Formulir (Forms):\n{forms}\n\n"
        f"Skrip (Scripts):\n{scripts}"
    ).strip()

    return [
        {
            "role": "system",
            "content": (
                "Anda adalah pakar keamanan siber yang menganalisis halaman web berdasarkan konten HTML "
                "dan hasil prediksi awal dari sistem machine learning. Tugas Anda:\n"
                "1. Menentukan apakah URL ini PHISHING atau TIDAK PHISHING.\n"
                "2. Memberikan alasan utama (maks. 3 kalimat).\n"
                "3. Meringkas tujuan halaman web (maks. 2 kalimat).\n"
                "4. Menyebutkan apakah ada bagian konten mencurigakan (maks. 2 kalimat).\n"
                "5. Jika PHISHING, berikan saran tindakan pengguna (maks. 2 kalimat).\n"
                "Jangan gunakan istilah teknis seperti 'confidence', 'prediksi awal', atau 'akurasi model'. \n"
                "Fokus hanya pada penjelasan konten dan ciri-ciri umum phishing.\n"
                "Tulis jawaban Anda dalam Bahasa Indonesia, nada percaya diri, dan dalam format yang diminta."
            )
        },
        {
            "role": "user",
            "content": (
                f"Data analisis URL:\n"
                f"- Prediksi awal model: {prediction}\n"
                f"- Confidence awal: {confidence}\n"
                f"- Confidence setelah penyesuaian: {adjusted}\n"
                f"- Domain terpercaya: {trusted_str}\n"
                f"- Prediksi akhir: {final_prediction}\n\n"
                f"- Konten yang diekstrak:\n{full_content}\n\n"
                "Silakan berikan analisis dalam format berikut:\n\n"
                "Prediksi: [PHISHING / TIDAK PHISHING]\n\n"
                "Alasan:\n[...]\n\n"
                "Ringkasan Halaman:\n[...]\n\n"
                "Konten Mencurigakan:\n[...]\n\n"
                "Tindakan:\n[...]"
            )
        }
    ]


def build_email_prompt(data: Dict[str, Any]) -> List[Dict[str, str]]:
    prediction = data.get("prediction", "tidak tersedia").upper()
    confidence = round(data.get("confidence", 0) * 100, 2)
    adjusted = round(data.get("adjusted_confidence", 0) * 100, 2)
    trusted = data.get("trusted_domain", False)
    trusted_str = "YA" if trusted else "TIDAK"
    email = data.get("value", "alamat tidak tersedia")
    features = data.get("features", {})
    final_prediction = data.get("final_prediction", "tidak tersedia").upper()

    # Format fitur menjadi daftar bullet
    features_str = "\n".join(f"- {k.replace('_', ' ').capitalize()}: {v}" for k, v in features.items())

    return [
        {
            "role": "system",
            "content": (
                "Anda adalah pakar keamanan siber. Tugas Anda adalah menjelaskan apakah sebuah alamat email tergolong PHISHING atau TIDAK PHISHING, "
                "berdasarkan alamat email dan hasil prediksi akhir sistem. Tugas Anda:\n"
                "1. Menentukan apakah email PHISHING atau TIDAK PHISHING.\n"
                "2. Memberikan alasan utama (maks. 3 kalimat).\n"
                "3. Menjelaskan karakteristik teknis email secara ringkas (maks. 3 kalimat).\n"
                "4. Memberikan kesimpulan apakah email dapat dipercaya (maks. 2 kalimat).\n"
                "Jangan sebutkan istilah teknis seperti 'confidence', 'prediksi awal', atau 'akurasi model'. Fokus hanya pada isi, ciri-ciri phishing, dan kredibilitas domain.\n"
                "Fokuslah pada ciri-ciri umum phishing seperti penggunaan domain gratis, nama acak, ketidaksesuaian pengirim dengan isi email, dan sebagainya.\n"
                "Tulis jawaban Anda dalam Bahasa Indonesia, ringkas dan meyakinkan dengan gaya percaya diri serta to the point."
            )
        },
        {
            "role": "user",
            "content": (
                f"Data analisis email:\n"
                f"- Alamat email: {email}\n"
                f"- Prediksi awal model: {prediction}\n"
                f"- Confidence awal: {confidence}\n"
                f"- Confidence setelah penyesuaian: {adjusted}\n"
                f"- Domain terpercaya: {trusted_str}\n"
                f"- Prediksi akhir: {final_prediction}\n\n"
                "Silakan berikan analisis dalam format berikut:\n\n"
                "Prediksi: [PHISHING / TIDAK PHISHING]\n\n"
                "Alasan:\n[...]\n\n"
                "Karakteristik Teknis:\n[...]\n\n"
                "Kesimpulan Kepercayaan:\n[...]"
            )
        }
    ]