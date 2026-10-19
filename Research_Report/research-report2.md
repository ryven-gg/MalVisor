# MalVisor — Research Report 2

**Topik:** Pengembangan MalVisor sebagai platform analisis *Portable Executable* (PE) yang statis, defensif, edukatif, dapat direproduksi, dan transparan terhadap ketidakpastian.  
**Tanggal penyusunan:** 19 Oktober 2026  
**Status:** Dokumen sintesis dan rencana riset; **bukan** hasil pengujian empiris.  
**Sumber utama:** (1) laporan ide dan penilaian Grok yang diberikan pengguna dalam percakapan; (2) evaluasi dan rekomendasi arsitektur dalam diskusi *deep-research* MalVisor sebelumnya. Tidak ada pencarian web atau validasi benchmark tambahan untuk penyusunan dokumen ini.

---

## 1. Ringkasan eksekutif

MalVisor direkomendasikan untuk diposisikan **bukan sebagai pengganti Ghidra atau radare2**, tetapi sebagai lingkungan kerja analisis PE yang berfokus pada **bukti, penjelasan, perbandingan parser, ketidakpastian, dan pembelajaran**.

**Tiga prinsip desain utama:**

1. **Evidence-first:** setiap finding mempunyai jejak bukti yang dapat ditelusuri ke offset PE, field header, byte, atau rentang instruksi yang berhasil dianalisis.
2. **Uncertainty-aware:** hasil observasi dipisahkan dari inferensi. Confidence pada ekstraksi tidak boleh disalahartikan sebagai probabilitas bahwa berkas bersifat berbahaya.
3. **Reproducible by design:** laporan mencatat checksum input, versi engine/parser, konfigurasi, dan keterbatasan sehingga hasil bisa diverifikasi pada input yang sama.

**Kombinasi fitur yang paling menjanjikan berdasarkan pembahasan:** *parser differential testing*, *evidence provenance graph*, panel interpretasi alternatif, visualisasi PE/CFG berbasis Cytoscape, lalu pemetaan kemampuan defensif dan *learning mode*. Kombinasi ini adalah **hipotesis diferensiasi produk**, bukan klaim kebaruan ilmiah yang sudah terbukti.

**Batas keamanan:** MalVisor hanya membaca artefak yang sudah ada dan diotorisasi. Tidak menjalankan malware, melakukan unpacking, injection, live analysis, atau mengunduh sampel malware otomatis.

---

## 2. Ruang lingkup dan asumsi

### Termasuk

- Parsing struktur PE dan pemeriksaan konsistensi metadata.
- Pembacaan disassembly statis, dengan pelaporan batas cakupan dan ketidakpastian.
- Perhitungan entropy, indikator struktur, ekstraksi string/resource, serta pemetaan import/export/ordinal.
- Perbandingan hasil beberapa parser pada input yang sama.
- Bukti yang menunjuk lokasi pada berkas, disassembly, dan laporan eksternal.
- Visualisasi offline/local dari struktur, CFG parsial, perbedaan, evidence, dan uncertainty.
- Pengujian menggunakan PE sintetis nonfungsional, fixture benign, dan laporan statis prabuat.
- Ekspor laporan dan materi pembelajaran.

### Tidak termasuk

- Menjalankan file yang dianalisis, termasuk di sandbox.
- Dynamic instrumentation, emulasi perilaku, injeksi proses, atau analisis jaringan langsung.
- Unpacking atau deobfuscation dinamis.
- Pengambilan malware secara otomatis dari repositori publik.
- Klaim bahwa keberadaan satu API, string, atau entropy tinggi membuktikan aktivitas berbahaya.

### Asumsi yang masih perlu diperiksa

- Arsitektur MalVisor sudah atau direncanakan memiliki parsing PE, Capstone untuk disassembly, dan Cytoscape untuk tampilan graf. Detail implementasi repositori saat ini **tidak diverifikasi** dalam dokumen ini.
- Penilaian novelty, difficulty, security risk, dan adoption pada tabel Grok adalah **estimasi kualitatif**, bukan hasil survei pasar atau studi literatur sistematis.

---

## 3. Inventaris usulan dari laporan Grok

### 3.1 Fitur defensif dan pendidikan

| Ide | Fungsi dan manfaat | Novelty (Grok) | Edukasi | Kesulitan | Risiko | Adopsi |
|---|---|---|---|---|---|---|
| PE structure anomaly distance | Mengukur penyimpangan header, alignment, section dan data-directory; menjelaskan alasan temuan | Medium–High | High | Medium | Very Low | High |
| Import/export/ordinal capability map | Relasi API teramati → kemungkinan kemampuan → ATT&CK/CAPEC/kontrol defensif beserta confidence | Medium | Very High | Medium | Low | High |
| Section entropy + packing indicators | Dashboard entropy, rasio ukuran, baseline, indikasi packer; bukan diagnosis pasti | Low–Medium | High | Low–Medium | Low | Medium–High |
| String & resource classification | Kategori URL, path, registry key, error message, icon, manifest, version info dengan konteks defensif | Medium | High | Medium | Low | High |
| Learning-mode quiz/challenge | Pertanyaan dari hasil analisis, petunjuk bertahap, dan konteks ATT&CK | High | Very High | Medium | None | High |

### 3.2 Skenario pembelajaran menggunakan artefak aman

| Ide | Rancangan | Novelty (Grok) | Edukasi | Kesulitan | Risiko | Adopsi |
|---|---|---|---|---|---|---|
| Synthetic PE mutation playground | Keluarga PE sintetis nonfungsional: checksum salah, section overlap, directory terpotong, alignment tak lazim | High | Very High | Medium–High | None | High |
| Benign vs indicator-bearing samples | Perbandingan file benign dengan contoh indikator statis berlabel; ajarkan false positive | Medium | High | Low–Medium | Low | High |
| Pre-generated report ingestion | Impor JSON/YAML laporan statis dari tool lain dan bandingkan dengan observasi MalVisor | Medium | High | Medium | Very Low | Medium–High |

**Catatan:** kategori “Risk: None” dan “Very Low” adalah klaim dari sumber ide. Pada implementasi nyata tetap ada risiko parser crash, konsumsi sumber daya, penanganan input tidak tepercaya, metadata sensitif, dan keamanan distribusi sampel.

### 3.3 Explainability, parser research, dan aksesibilitas

| Ide | Hasil yang diinginkan | Novelty (Grok) | Edukasi | Kesulitan | Risiko | Adopsi |
|---|---|---|---|---|---|---|
| Evidence provenance graph | Finding → bukti → exact offset/field/instruction range; inspeksi bytes/disassembly | Medium–High | Very High | Medium | None | High |
| Parser differential testing harness | Membandingkan MalVisor dengan pefile/LIEF; klasifikasi divergence | High | High | Medium–High | Low | High |
| Interactive PE layout / directory / overlay | Peta file zoomable; warna severity/confidence; keyboard dan screen reader | Medium | High | Medium | None | High |
| Uncertainty & alternative interpretations | Menampilkan penjelasan benign vs interpretasi mencurigakan yang mungkin | High | Very High | Medium | None | High |

---

## 4. Dataset dan materi pengujian yang diusulkan

| Kelompok | Contoh yang disebut Grok | Kegunaan | Kualifikasi dan tindakan sebelum penggunaan |
|---|---|---|---|
| Data fitur PE berlabel | EMBER, SOREL-20M, PE-Machine-Learning | Studi statistik fitur statis dan perbandingan | Verifikasi lisensi, label, format, provenance, serta apakah yang tersedia berupa fitur atau executable |
| Metadata keluarga/sampel riset | Malpedia | Referensi kategori dan metadata | Periksa persyaratan akses dan lisensi; utamakan metadata/laporan, bukan executable |
| Repositori sampel malware | MalwareBazaar, VirusShare, VX Underground | Potensi sumber artefak riset | **Bukan rekomendasi untuk download otomatis.** Pilih publikasi fitur statis atau contoh yang aman dan berizin; tidak diperlukan untuk MVP |
| Malformed-PE corpora | Dataset riset akademik tentang PE parsing robustness | Differential robustness | Validasi ketersediaan, label expected behavior dan lisensi; jika belum ada, gunakan fixture sintetis nonfungsional |
| Negative controls | Binary sistem Windows dan software bersih yang diizinkan | Mengukur temuan pada benign inputs | Periksa hak redistribusi; gunakan berkas sendiri/diizinkan, jangan paketkan ulang file proprietari tanpa izin |
| Fixture lokal sintetis | PE dummy/nonfungsional dengan field rusak terkontrol | Unit test, regression, demonstrasi kelas | Favorit untuk MVP karena sepenuhnya offline dan dapat diberi expected outcomes eksplisit |

**Pembedaan metodologis penting:** label *benign/malicious* pada dataset tidak otomatis menjadi *ground truth* untuk **setiap indikator statis**. Precision/recall per finding membutuhkan label tingkat finding atau anotasi pakar, bukan sekadar label tingkat berkas.

---

## 5. Evaluasi prioritas hasil pembahasan

Skala prioritas berikut adalah **rekomendasi proyek**, bukan skor objektif.

| Fitur | Prioritas | Alasan |
|---|---|---|
| Evidence provenance graph / engine | **P0** | Semua interpretasi harus dapat dilacak ke bukti |
| Parser differential testing | **P0** | Membuka jalur riset robustness dan regression |
| Uncertainty / alternative interpretations | **P0** | Mencegah overclaim, pembeda produk |
| Interactive PE layout | **P1** | Memvisualisasikan evidence dan struktur file |
| PE anomaly explanations | **P1** | Membuat output parser lebih dapat dipahami |
| Multi-layer Cytoscape visualization | **P1** | Menyatukan struktur, CFG parsial, bukti, dan ketidakpastian |
| Import capability / control mapping | **P1** | Mengaitkan artefak dengan pembelaan, namun perlu batas confidence yang jelas |
| Learning mode | **P2** | Nilai edukasi tinggi setelah evidence schema stabil |
| Synthetic mutation playground | **P2** | Berguna untuk kelas dan riset, tetapi sebaiknya berbasis fixture terbatas |
| ATT&CK Navigator, STIX, SARIF, YARA, capa integrations | **P3** | Berguna untuk interoperabilitas, tetapi dapat menambah kompleksitas sebelum core stabil |

**Keputusan:** implementasi P0 dahulu, dilanjutkan P1 secara bertahap. Jangan membangun seluruh daftar sekaligus.

---

## 6. Tiga temuan metodologis penting

### 6.1 Confidence bukan probabilitas malware

Contoh: API `VirtualAlloc` terdeteksi dalam import table.

- **Observasi:** nama import `VirtualAlloc` ditemukan pada lokasi tertentu dalam PE.
- **Kemungkinan fungsi:** berkas mungkin mengalokasikan memori secara dinamis.
- **Kepastian observasi:** dapat tinggi jika parsing valid dan lokasi terverifikasi.
- **Kekuatan inferensi:** lebih terbatas, sebab API dapat digunakan aplikasi normal.
- **Interpretasi alternatif:** alokasi memori untuk kebutuhan sah.
- **Kesimpulan yang tidak dibenarkan:** “malicious: 85%” hanya dari satu import.

Sebaiknya simpan `observation_confidence`, `inference_strength`, `limitations`, dan `alternative_explanations` secara terpisah. Jika kalibrasi statistik belum dilakukan, gunakan level kualitatif dengan kriteria terdokumentasi, bukan persentase semu.

### 6.2 Divergence antarparser bukan otomatis bug

Klasifikasi awal:

1. **Equivalent:** representasi berbeda, makna sama.
2. **Semantic Difference:** interpretasi field atau boundaries berbeda secara substantif.
3. **Unsupported:** salah satu parser sengaja tidak mendukung fitur.
4. **Malformed Input:** input melanggar constraint yang terdokumentasi.
5. **Suspected Parser Defect:** penyimpangan dari perilaku yang diharapkan setelah pemeriksaan lebih lanjut.

Klasifikasi “Suspected” memerlukan bukti dan reproduksi, bukan vonis otomatis. Hasil parser sebaiknya dinormalisasi sebelum dibandingkan.

### 6.3 Disassembly dan CFG memiliki coverage parsial

Static disassembly tidak menjamin semua fungsi/instruksi ditemukan. Indirect jumps, data/code ambiguity, batas fungsi, dan referensi yang tidak terselesaikan membuat CFG dapat tidak lengkap.

Laporan disassembly harus menyertakan:

- Rentang byte yang telah dianalisis dan basis metode discovery.
- Unresolved branches/edges serta asumsi target.
- Area ambigu atau tak terklasifikasi.
- Indikator cakupan yang didefinisikan jelas; jangan menyatakan “100% code coverage” tanpa ground truth.

---

## 7. Arsitektur MalVisor yang disarankan

```text
Authorized PE / Synthetic Fixture / Pre-generated Static Report
                           |
                           v
                    Input Validation
                (size limits, checksums)
                           |
                           v
  +-------------------------------------------------+
  |                Static Analysis Core             |
  | PE Parser | Disassembler | Differential Adapter |
  +-------------------------------------------------+
                           |
                           v
  +-------------------------------------------------+
  |             Evidence & Provenance Engine        |
  | offsets | observations | inference | uncertainty|
  | parser attribution | reproducibility metadata  |
  +-------------------------------------------------+
                           |
                           v
  +------------------+------------------------------+
  |                  |                              |
  v                  v                              v
JSON/CLI report   Cytoscape UI                Learning mode
                 PE layout / CFG             Quiz / hints /
                 evidence / diff             guided exercises
                 uncertainty
```

### 7.1 Model data inti

- **Artifact:** SHA-256, ukuran, tipe, asal yang diizinkan, konfigurasi analisis.
- **Observation:** apa yang secara langsung ditemukan, lokasi fisik/logis, parser/metode pengambilnya.
- **Evidence:** rentang offset/byte/field/instruksi, checksum atau representasi terbatas, hubungan antar-finding.
- **Inference:** makna yang mungkin dari satu/lebih observasi; aturan yang digunakan dan penjelasan alternatif.
- **Disagreement:** dua atau lebih interpretasi parser terhadap field yang dinormalisasi.
- **Limitation:** bagian tak dianalisis, error parser, unresolved flow, dan konteks yang hilang.
- **Lesson:** pertanyaan, hint, jawaban, referensi evidence ID.

### 7.2 Evidence Reproducibility Contract (usulan tambahan)

Fitur ini bukan item eksplisit dalam tabel Grok. Ia disimpulkan dari kebutuhan provenance dan reproducibility pada evaluasi MalVisor.

```json
{
  "schema_version": "1.0.0",
  "input_sha256": "<sha256-of-authorized-file>",
  "engine_version": "<version>",
  "parser_versions": {
    "malvisor": "<version>",
    "reference_parser": "<version>"
  },
  "analysis_config": {
    "static_only": true,
    "target_format": "PE"
  },
  "findings": [
    {
      "id": "finding-001",
      "kind": "observed_import",
      "observation": "Import entry present",
      "evidence_ids": ["evidence-001"],
      "observation_confidence": "high",
      "inference_strength": "context-dependent",
      "alternative_explanations": ["Legitimate memory management"]
    }
  ],
  "evidence": [
    {
      "id": "evidence-001",
      "source": "pe_import_table",
      "file_offset": null,
      "rva": null,
      "verification_status": "location-pending"
    }
  ],
  "unresolved": [],
  "limitations": []
}
```

Contoh tersebut **skema ilustratif**, bukan output engine nyata; offset sengaja `null` karena belum ada file yang dianalisis. Untuk determinisme lintas mesin, tetapkan normalisasi nama field, urutan temuan, serialisasi JSON, parser versions, serta penghilangan timestamp nondeterministik dari hash laporan.

---

## 8. Eksperimen dan metrik riset

| Eksperimen | Pertanyaan riset | Metrik | Desain minimum / kontrol |
|---|---|---|---|
| Parser robustness | Seberapa tahan parser terhadap PE sintetis malformed? | Crash-free rate; parse success; error classification; waktu proses | Fixture terlabel; variasi kesalahan terkontrol; pembanding pefile/LIEF |
| Differential analysis | Kapan parser menghasilkan interpretasi berbeda? | Divergence rate menurut kelas; false divergence setelah normalisasi | Atribut yang setara dibandingkan; review manual untuk kategori ambigu |
| Static indicator validity | Apakah temuan sesuai label indikator? | Precision, recall, F1 per indikator | Dataset dengan **label indikator tingkat finding**; kontrol benign |
| Benign false positives | Seberapa sering indikator memunculkan temuan pada benign? | Finding rate / FPR dengan definisi threshold eksplisit | Sampel benign berizin dan beragam; laporkan karakteristik sampling |
| Provenance explainability | Apakah analisis lebih mudah diaudit? | Waktu menemukan bukti; tingkat ketepatan; skor Likert | Tugas sama dengan/tanpa evidence graph; peserta dan randomisasi dijelaskan |
| Visualization efficacy | Apakah peta PE mempercepat penemuan section tidak lazim? | Time-to-insight; akurasi; error rate | Studi tugas dengan baseline tabel tradisional |
| Learning outcomes | Apakah learning mode meningkatkan pemahaman PE? | Skor pre/post dan retensi; ukuran efek | Soal setara, kondisi pembanding jika memungkinkan |
| Reproducibility | Apakah input/config sama menghasilkan observasi sama? | Hash output kanonik; jumlah deviasi; versi | Re-run pada platform/versi yang dikontrol |

**Perhatian:** tidak ada hasil angka, ukuran sampel aktual, ataupun p-value yang tersedia pada dua sumber percakapan. Semua eksperimen di atas adalah **rencana**. Klaim “novelty high” perlu diuji lewat tinjauan pustaka serta perbandingan fungsional dengan alat existing.

---

## 9. Integrasi format dan ekosistem

| Integrasi | Manfaat | Syarat untuk pengembangan |
|---|---|---|
| capa-compatible capability tags / import | Memanfaatkan taksonomi kemampuan tanpa membangun ulang engine | Bedakan tag dari temuan capa aktual; catat asal dan versi rules |
| MITRE ATT&CK Navigator export | Memvisualisasikan relasi kemampuan dan teknik | Tandai mapping sebagai hipotesis statis, bukan perilaku teramati |
| CAPEC reference mapping | Konteks pendidikan pola serangan | Catat evidence dan kekuatan relasi; hindari mapping otomatis yang terlalu luas |
| STIX 2.1 export | Interoperabilitas data ancaman | Gunakan tipe dan semantik yang sesuai, jangan mengubah indikasi statis menjadi klaim insiden |
| YARA static rules / matching | Pelajaran signature statis | Fokus fixture aman; dokumentasi false-positive dan batas pengujian |
| SARIF export | Pelaporan static analysis dan integrasi CI | Pemetaan lokasi/aturan finding yang masuk akal untuk artefak binary |
| pefile/LIEF adapters | Parser differential dan perbandingan hasil | Normalisasi model field, versi parser terkunci |
| JSON schema | Interoperabilitas dengan visualizer atau pipeline | Versioning dan uji kompatibilitas maju/mundur |

Integrasi ini tidak semuanya diperlukan untuk versi awal. **P3** dapat dikerjakan setelah kontrak finding dan evidence stabil.

---

## 10. Diferensiasi terhadap tool yang sudah mapan

| Alat/kategori | Kekuatan umum yang relevan | Fokus pembeda yang diusulkan untuk MalVisor |
|---|---|---|
| Ghidra | Reverse engineering dan disassembly komprehensif | Pendidikan bertahap, penjelasan uncertainty, provenance sebagai konsep UI utama |
| radare2 | Toolkit analisis binary yang fleksibel | Navigasi visual untuk siswa serta perbandingan parser terstruktur |
| capa | Identifikasi kapabilitas berdasarkan aturan | Konteks PE structure, provenance lintas-parser, alternatif interpretasi, latihan interaktif |
| PE viewers biasa | Inspeksi struktur/header/tabel | Differential parsing, multi-layer evidence graph, metodologi pengujian reproducible |

Tabel ini menyatakan **arah positioning**, bukan bukti bahwa alat pembanding sama sekali tidak memiliki fitur serupa. Perbandingan fitur dan kebaruan memerlukan riset langsung terhadap versi tools terkini.

---

## 11. Rencana implementasi bertahap

### Phase 0 — Audit fondasi, fixture dan spesifikasi

- Audit repositori yang ada, versi dependency, pipeline parsing dan antarmuka analisis tanpa mengubahnya dulu.
- Definisikan batas static-only, kebijakan input dan kapasitas maksimum.
- Tetapkan *schema* minimal Observation/Evidence/Inference/Disagreement.
- Siapkan fixture PE sintetis nonfungsional dan benign terotorisasi.
- Buat unit test untuk parser outcomes serta metadata provenance.

**Exit criteria:** fixture valid/invalid bisa dibedakan dengan error yang terkendali; input tak valid tidak menyebabkan process crash yang tak tertangani pada test suite.

### Phase 1 — P0: evidence + differential + uncertainty

- Hubungkan extraction dengan evidence IDs dan exact locations jika tersedia.
- Tambahkan adapter parser pembanding, normalisasi field dan divergence classes.
- Buat panel tekstual observasi vs inferensi vs alternatif.
- Simpan versi parser, konfigurasi dan hash input dalam laporan JSON kanonik.
- Regression tests untuk semua kasus yang ditemukan.

**Exit criteria:** sebuah finding bisa ditelusuri ke lokasi dan metode; divergence dapat direproduksi; interpretasi tanpa bukti tidak tampil sebagai fakta.

### Phase 2 — P1: visualisasi dan penjelasan

- PE file-layout explorer untuk section, directory, overlay dan hasil sanity checks.
- Cytoscape layers untuk hubungan structure → findings → evidence serta CFG **parsial**.
- Severity/confidence dibedakan secara visual; navigasi keyboard, high-contrast, dan deskripsi alternatif.
- Baseline entropy dan classed strings/resources sebagai indikator, bukan verdict.
- Capability mapping beserta defensive controls jika tersedia bukti memadai.

**Exit criteria:** setiap visualisasi konsisten dengan data JSON dan dapat ditelusuri kembali ke bukti.

### Phase 3 — P2: pengalaman belajar dan research kit

- Tantangan otomatis yang hanya didasarkan pada temuan tervalidasi.
- Synthetic mutation playground dari fixture terbatas dan nonfungsional.
- Export/import report statis dan pengalaman membandingkan interpretasi.
- Studi pengguna kecil untuk waktu inspeksi bukti dan pemahaman konsep.

**Exit criteria:** tugas edukasi dapat diperiksa jawabannya dari evidence; hasil eksperimen terdokumentasi dan dapat diulang.

### Phase 4 — P3: interoperabilitas

- Evaluasi capa tags, ATT&CK Navigator, SARIF, STIX, dan YARA menurut kebutuhan pengguna nyata.
- Tulis *mapping tests* dan dokumentasi keterbatasan semantik.
- Pertahankan static-only, offline-first dan format output yang stabil.

---

## 12. Risks, mitigasi, dan kualitas ilmiah

| Risiko | Dampak | Mitigasi |
|---|---|---|
| False positive pada entropy/import/string | Pembaca menarik kesimpulan keliru | Pisahkan observasi dari inferensi dan tampilkan interpretasi benign |
| Persentase confidence tanpa kalibrasi | Memberi kesan kuantitatif palsu | Gunakan kategori kualitatif sampai diuji terhadap label tepercaya |
| Parser crash / denial-of-service dari input malformed | Stabilitas aplikasi rendah | Batas ukuran, batas sumber daya, error handling, fuzz/fixture offline, regression |
| Disassembly/CFG tidak lengkap | Visualisasi tampak lebih pasti dari kenyataan | Tampilkan unresolved edges, area tak dianalisis dan metrik coverage terdefinisi |
| Parser disagreement salah diklasifikasikan | Klaim bug palsu | Normalisasi dan review manual kasus suspect |
| Dataset dan lisensi tidak jelas | Risiko distribusi dan validitas riset | Verifikasi akses/lisensi, dokumentasikan provenance, pilih feature-only/synthetic |
| Scope creep | Fondasi rapuh dan sulit diuji | Gerbang prioritas P0 → P1 → P2 → P3 |
| Ketergantungan pada semantik framework eksternal | Mismatch dan data loss | Adapter berversi, schema contracts, integration tests |

---

## 13. Klaim, bukti, dan celah riset

### Didukung oleh sumber percakapan

- Ada 12 usulan utama yang terbagi ke fitur edukatif, skenario sintetis, dan visualisasi/robustness.
- Grok merekomendasikan gabungan parser differential, provenance graph, learning mode, ATT&CK/defensive mapping, serta multi-layer Cytoscape.
- Evaluasi lanjutan merekomendasikan **P0 evidence/differential/uncertainty**, memisahkan observasi dengan dugaan, dan tidak mengklaim CFG lengkap.
- Gagasan **Evidence Reproducibility Contract** muncul sebagai rekomendasi sintesis pembahasan.

### Belum diverifikasi / memerlukan riset atau implementasi

- Apakah kombinasi MalVisor benar-benar baru dibanding versi Ghidra, radare2, capa, dan tool PE viewer saat ini.
- Ketersediaan, lisensi, karakteristik, serta keterwakilan dataset yang diusulkan.
- Baseline kuantitatif parser robustness, precision/recall, FPR, usability dan learning impact.
- Biaya implementasi, performa pada hardware target, dan kemampuan aktual kode MalVisor yang sudah ada.
- Seberapa baik ATT&CK/CAPEC mapping dapat dibuat dengan evidence yang terbatas pada informasi statis.

---

## 14. Kesimpulan final

**Pilihan strategis:** bangun MalVisor sebagai **platform riset/edukasi analisis PE berbasis bukti**. Keunggulannya bukan memperbanyak label ancaman, melainkan membuat setiap temuan lebih **dapat diperiksa, dapat dibandingkan, dan dapat dipelajari**.

**Urutan pengembangan yang disetujui dalam sintesis:**

1. Model bukti dan provenance.
2. Differential parsing dengan klasifikasi divergence.
3. Representasi ketidakpastian dan alternatif interpretasi.
4. Visualisasi interaktif PE/layout/CFG/evidence.
5. Pemetaan kemampuan defensif dan learning mode.
6. Integrasi eksternal setelah schema matang.

**Pertanyaan riset utama yang disarankan:**

> Apakah visualisasi provenance, ketidakpastian, dan perbedaan hasil parser dalam satu platform statis dapat meningkatkan ketepatan interpretasi dan kemampuan audit pengguna saat menganalisis struktur PE dibanding output parser konvensional?

**Pernyataan prinsip MalVisor:**

> *Show what is observed, why it is inferred, where the evidence lives, and what remains unknown.*

Ini adalah dasar yang lebih kuat untuk README, roadmap GitHub, eksperimen reproducible, dan calon publikasi ilmiah dibanding sekadar menambah satu lagi “malware score” tanpa kalibrasi.

---

## Lampiran A — Asal informasi dan status validasi

- **[GROK / input pengguna]** Inventaris 12 fitur/scenario, estimasi novelty/difficulty/risk/adoption, daftar dataset, gagasan eksperimen, integrasi, positioning, dan highest-leverage combination.
- **[EVALUASI / diskusi MalVisor]** Prioritas P0–P3, penolakan confidence palsu, pengelompokan divergence, pengungkapan CFG parsial, evidence-first architecture, dan rekomendasi implementasi bertahap.
- **[SINTESIS DOKUMEN]** Kontrak data yang dinormalisasi, contoh JSON, exit criteria tiap fase, kontrol validitas eksperimen, dan daftar gap riset. Semua ini merupakan desain yang diusulkan, bukan fitur yang telah dibangun.

**Status bukti:** laporan ini tidak menyajikan hasil pengukuran empiris baru, hasil inspeksi kode repo MalVisor, ataupun verifikasi sumber web independen. Label prioritas dan novelty tidak boleh dikutip sebagai temuan yang teruji tanpa penelitian tambahan.
