from typing import List, Dict, Any

def build_url_prompt(data: Dict[str, Any]) -> List[Dict[str, str]]:
    def limit_text(arr, max_len=400):
        if not isinstance(arr, list):
            return ""
        joined = "\n".join(arr)
        return (joined[:max_len] + '...') if len(joined) > max_len else joined

    titles = limit_text(data.get("titles", []), max_len=200)
    heads = limit_text(data.get("heads", []), max_len=800)
    body = limit_text(data.get("body", []), max_len=1200)
    scripts = limit_text(data.get("scripts", []), max_len=1000)
    prediction = data.get("prediction", "tidak tersedia").upper()
    confidence = round(data.get("confidence", 0) * 100, 2)
    final_prediction = data.get("final_prediction", "tidak tersedia").upper()
    trusted = data.get("trusted_domain", False)
    trusted_str = "YA" if trusted else "TIDAK"

    full_content = (
        f"Judul Halaman (Title):\n{titles}\n\n"
        f"Bagian Head:\n{heads}\n\n"
        f"Formulir (Body):\n{body}\n\n"
        f"Skrip (Scripts):\n{scripts}"
    ).strip()

    return [
        {
            "role": "system",
            "content": (
                "Anda adalah pakar keamanan siber yang menganalisis halaman web berdasarkan isi web dari title, head, body, script serta hasil prediksi dari sistem machine learning. "
                "Tugas Anda:\n"
                "1. Tentukan apakah halaman ini phishing atau legitimate berdasarkan hasil prediksi model:\n"
                "   - Jika halaman ini phishing, beri alasan kenapa halaman ini terdeteksi sebagai phishing, dengan menyebutkan elemen mencurigakan yang ditemukan, "
                "seperti formulir login, iframe mencurigakan, atau skrip berbahaya. Jelaskan mengapa elemen-elemen ini membuat halaman terindikasi phishing (maks. 3 kalimat).\n"
                "   - Jika halaman ini legitimate, beri alasan mengapa halaman ini dianggap sah, dengan menyebutkan bahwa tidak ditemukan elemen mencurigakan, "
                "namun jika ada elemen yang terlihat mencurigakan (misalnya formulir atau iframe), beri penjelasan bahwa elemen tersebut sebenarnya aman untuk diakses (maks. 3 kalimat).\n"
                "2. Ringkasan Tujuan Halaman:\n"
                "   Ringkas tujuan atau fungsi dari halaman web ini berdasarkan konten title dan body yang ada, apakah itu tutorial, artikel, blog post, atau lainnya (maks. 3 kalimat).\n"
                "3. Identifikasi Elemen Mencurigakan:\n"
                "   Jika halaman ini phishing, sebutkan elemen-elemen yang mencurigakan, seperti formulir login yang tidak sah, iframe dari domain tidak terpercaya, atau skrip berbahaya. "
                "Jika halaman ini legitimate, sebutkan satu elemen yang mungkin terlihat mencurigakan, tetapi sebenarnya aman untuk diakses, seperti form pencarian atau iframe yang aman (maks. 3 kalimat).\n"
                "4. Jika halaman ini terdeteksi phishing, beri saran tindakan yang jelas untuk pengguna, seperti memverifikasi domain, tidak memasukkan data pribadi, atau menggunakan alat keamanan seperti browser extension untuk memeriksa keaslian halaman (maks. 3 kalimat).\n"
                "Catatan Khusus: Jika domain halaman **tidak terpercaya** namun model prediksi mengatakan **legitimate**, **abaikan saja** dan tidak perlu menyebutkan domain tidak terpercaya kepada pengguna, baik dalam alasan, ringkasan halaman, konten mencurigakan, maupun tindakan.\n"
                "Jangan gunakan istilah teknis seperti 'confidence', 'prediksi awal', atau 'akurasi model'. Fokus pada analisis konten halaman dan tanda-tanda phishing yang bisa dikenali oleh pengguna awam. "
                "Tulis jawaban Anda dalam Bahasa Indonesia dengan nada percaya diri."
            )
        },
        {
            "role": "user",
            "content": (
                f"Data analisis URL:\n"
                f"- Prediksi awal model: {prediction}\n"
                f"- Confidence awal: {confidence}\n"
                f"- Domain terpercaya: {trusted_str}\n"
                f"- Prediksi akhir: {final_prediction}\n\n"
                f"- Konten yang diekstrak:\n{full_content}\n\n"
                "Silakan berikan analisis dalam format berikut:\n\n"
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