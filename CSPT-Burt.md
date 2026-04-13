# 📘 CSPT Burp Extension - Penjelasan Lengkap

## 📌 Ringkasan Eksekutif

**CSPT (Client-Side Path Traversal)** adalah ekstensi Burp Suite yang mendeteksi kerentanan path traversal dengan mencari parameter GET yang nilainya muncul kembali di path URL dari request lain dalam proxy history. Ini adalah kerentanan client-side yang dieksekusi melalui browser.

---

## 🏗️ Arsitektur Sistem

```
┌────────────────────────────────────────────────────────────┐
│          ClientSidePathTraversal (Main Class)              │
│  - Mengelola konfigurasi (scope, methods, false positives)│
│  - Menyimpan canary token untuk verifikasi manual         │
│  - Mengelola persistence data di project Burp            │
└────────────────────────────────────────────────────────────┘
                          ↓
    ┌─────────────────────┴─────────────────────┐
    ↓                                             ↓
┌─────────────────────────────┐   ┌──────────────────────────┐
│  ClientSidePathTraversalForm │   │ FalsePositivesForm      │
│  - UI untuk scan manual     │   │ - Manage whitelist      │
│  - Display sources & sinks  │   │ - Exclude false positives│
│  - Progress tracking        │   │ - Save/load rules       │
└─────────────────────────────┘   └──────────────────────────┘
                ↑                          ↑
                └──────────┬───────────────┘
                           ↓
        ┌──────────────────────────────────────┐
        │    CSPTScannerTask (Background Job)  │
        │  - Step 1: List Sources              │
        │  - Step 2: Find Reflections (Sinks)  │
        │  - Multi-threaded dengan SwingWorker │
        └──────────────────────────────────────┘
                    ↑              ↑
        ┌───────────┴──────────────┴────────────┐
        ↓                                        ↓
┌──────────────────────────┐   ┌─────────────────────────┐
│ ProxyFilterPotentialSource│   │ProxyFilterPotentialSink │
│ - Filter proxy history   │   │- Cari reflections      │
│ - Identifikasi GET params│   │- Match param values    │
│ - Simpan ke paramValue   │   │- Cek HTTP methods      │
│   Lookup                 │   │- Enforce sinkScope     │
└──────────────────────────┘   └─────────────────────────┘
```

---

## 🔎 Logika Deteksi Detail

### **1️⃣ Tahap 1: Identifikasi Sources (ProxyFilterPotentialSource.java)**

#### Kriteria Penerimaan Request sebagai Source:

```markdown
✅ MUST HAVE:
   └─ Method: GET
   └─ Response MIME Type: text/html
   └─ HTTP Status Code: < 400 (tidak error, boleh redirect 3XX)
   └─ Memiliki URL parameters (query string tidak kosong)
   └─ URL cocok dengan sourceScope regex pattern

✅ MUST NOT BE:
   └─ False positive (sudah ada di whitelist)
```

#### Pseudo Code:
```java
for (ProxyRequest request : proxyHistory) {
    // 1. Check response type
    if (response.mimeType != "text/html") continue;
    
    // 2. Check status code
    if (response.status >= 400) continue;
    
    // 3. Check request method
    if (request.method != "GET") continue;
    
    // 4. Check parameters exist
    if (request.parameters.isEmpty()) continue;
    
    // 5. Check scope regex
    if (!sourceScope.matches(request.url)) continue;
    
    // 6. Extract parameters
    for (param : request.parameters) {
        PotentialSource source = new PotentialSource(
            param.name,                    // "file"
            param.value.toLowerCase(),     // "admin.pdf" (lowercase!)
            request.url                    // full URL
        );
        
        // 7. Check if not false positive
        if (!checkIfFalsePositive(source)) {
            paramValueLookup.add(source.paramValue, source);
        }
    }
}
```

#### Data Structure Dihasilkan:
```
paramValueLookup = {
    "admin.pdf" → [
        PotentialSource(name="file", value="admin.pdf", url="https://app.com/page?file=admin.pdf&user=bob"),
        PotentialSource(name="doc", value="admin.pdf", url="https://app.com/page?doc=admin.pdf&lang=en")
    ],
    "users.csv" → [
        PotentialSource(name="export", value="users.csv", url="https://app.com/download?export=users.csv")
    ]
}
```

---

### **2️⃣ Tahap 2: Identifikasi Reflections/Sinks (ProxyFilterPotentialSink.java)**

#### Kriteria Request sebagai Sink:

```markdown
✅ MUST HAVE:
   └─ HTTP Method ada di sinkHTTPMethods (GET, POST, PUT, DELETE, dll)
   └─ URL cocok dengan sinkScope regex
   └─ Path URL mengandung value dari paramValueLookup (case-insensitive)

✅ MUST NOT BE:
   └─ OPTIONS request
```

#### Algoritma Matching Path:

```java
// Request sink yang diperiksa:
// GET /download/admin.pdf/page?other=param

HttpRequest sink = requestResponse.finalRequest();

// Split path by "/" delimiter
String[] pathSegments = sink.pathWithoutQuery().split("/");
// Result: ["", "download", "admin.pdf", "page"]

for (String segment : pathSegments) {
    // Compare lowercase (case-insensitive matching)
    String lowerSegment = segment.toLowerCase();
    
    // Cek apakah segment ada di paramValueLookup
    if (paramValueLookup.containsKey(lowerSegment)) {
        // MATCH FOUND!
        pathLookup.add(lowerSegment, 
            new PotentialSink(
                sink.method(),           // "GET"
                sink.url()               // "https://app.com/download/admin.pdf/page?other=param"
            )
        );
        return true; // This request is a sink
    }
}
```

#### Contoh Matching:

| Source | Value | Sink Request | Path Segments | Match? |
|--------|-------|---|---|---|
| `?file=admin.pdf` | `admin.pdf` | `GET /download/admin.pdf` | `["download", "admin.pdf"]` | ✅ YES |
| `?doc=invoice.pdf` | `invoice.pdf` | `GET /view/reports/invoice.pdf/details` | `["view", "reports", "invoice.pdf", "details"]` | ✅ YES |
| `?export=data` | `data` | `GET /api/export/list` | `["api", "export", "list"]` | ❌ NO (tidak ada match) |
| `?file=Test` | `test` (lowercase!) | `GET /files/test/show` | `["files", "test", "show"]` | ✅ YES (case-insensitive) |

#### Data Structure Dihasilkan:
```
pathLookup = {
    "admin.pdf" → [
        PotentialSink(method="GET", url="https://app.com/download/admin.pdf"),
        PotentialSink(method="POST", url="https://app.com/api/process/admin.pdf")
    ],
    "users.csv" → [
        PotentialSink(method="GET", url="https://app.com/export/users.csv/details")
    ]
}
```

---

### **3️⃣ Data Model Classes**

#### **PotentialSource.java**
```java
class PotentialSource {
    String paramName;      // "file"
    String paramValue;     // "admin.pdf" (LOWERCASE)
    String sourceURL;      // "https://app.com/page?file=admin.pdf"
    
    // Equality: Based on ALL 3 fields
    // Jika salah satu berbeda → dianggap source berbeda
}
```

#### **PotentialSink.java**
```java
class PotentialSink {
    String method;         // "GET", "POST", dll
    String url;           // "https://app.com/download/admin.pdf"
    
    // Equality: Based on method & url
    // Duplikasi akan di-deduplicate otomatis
}
```

---

## 🛡️ Mekanisme False Positive Prevention

### **1. False Positives List (Whitelist)**

```java
// Struktur data
falsePositivesList = Map<String, Set<String>>
    Key: parameter name (misal "file")
    Value: Set of URL regex patterns to skip

// Contoh:
falsePositivesList = {
    "file" → [
        "https://cdn\\.app\\.com/.*",     // Skip CDN patterns
        "https://static\\..*"              // Skip static domains
    ],
    "id" → [
        "https://app\\.com/user/\\d+.*"   // Skip user ID patterns
    ]
}

// Saat deteksi source:
PotentialSource source = new PotentialSource("file", "jquery.min.js", url);
if (checkIfFalsePositive(source)) {
    // Skip this source
    continue;
}
```

#### Cara Menambah False Positive:

1. UI: Klik kanan pada source → "Discard"
2. Pilih tipe: Parameter name atau URL regex
3. Masukkan pattern regex (misal: `.*\.js$` untuk file JS)
4. Settings otomatis tersimpan di project Burp

### **2. Scope Filtering (Regex Patterns)**

```java
// sourceScope: Membatasi URL mana yang diterima sebagai source
sourceScope = "https://myapp\\.com/page.*"
// Hanya scan requests ke myapp.com/page

// sinkScope: Membatasi URL mana yang diperiksa sebagai sink
sinkScope = "https://myapp\\.com/api.*"
// Hanya cek sinks di API endpoints

// Contoh konfigurasi:
sourceScope = ".*login.*|.*dashboard.*"  // Source dari login atau dashboard
sinkScope = ".*download.*|.*export.*"    // Sink di download atau export endpoints
```

### **3. HTTP Methods Filtering**

```java
sinkHTTPMethods = ["GET", "POST", "PUT"]
// Hanya cek sinks dengan method GET, POST, PUT
// Skip OPTIONS, DELETE, PATCH, dll
```

### **4. Response Type Filtering**

```java
// Hanya terima text/html responses
if (httpResponse.statedMimeType() != MimeType.HTML) {
    return false;
}
// Otomatis skip: CSS, JavaScript, Images, JSON, XML, dll
```

### **5. HTTP Status Code Filtering**

```java
// Abaikan error responses
if (httpResponse.statusCode() >= 400) {
    return false;
}
// Skip 404, 403, 500, 503, dll
// Tapi TERIMA 3XX redirects
```

### **6. Canary Token Verification (Manual)**

```java
// Generate canary token (12 random ASCII letters)
canary = "rKmNpQvWxYzA"

// Saat testing:
1. Klik "Copy URL With Canary"
   → "https://app.com/page?file=rKmNpQvWxYzA"

2. Paste & buka di browser

3. Monitor proxy history untuk sink requests

4. Jika sink path berisi canary:
   → REAL VULNERABILITY ✅
   → Bukan false positive
   
5. Jika sink path TIDAK berisi canary:
   → FALSE POSITIVE ❌
   → Abaikan / tambah ke whitelist
```

#### Implementasi di Passive Scan:

```java
// ClientSidePathTraversalPassiveScan.java
public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
    String path = baseRequestResponse.request()
                    .pathWithoutQuery()
                    .toLowerCase();
    
    // Deteksi jika path mengandung canary token
    if (path.contains(cspt.getCanary().toLowerCase())) {
        // Buat audit issue baru
        return auditResult(
            AuditIssueSeverity.MEDIUM,
            AuditIssueConfidence.FIRM,
            "Potential Client-Side Path Traversal"
        );
    }
    return null;
}
```

---

## 📊 Alur Kerja Lengkap

```
START
  ↓
[User clicks "Scan" in UI]
  ↓
[CSPTScannerTask.doInBackground() executed in background]
  ↓
┌─────────────────────────────────────────────────────────┐
│ STEP 1: IDENTIFY SOURCES                               │
│ • Iterate through all proxy history requests           │
│ • ProxyFilterPotentialSource filters each request      │
│ • Criteria: GET, HTML response, < 400 status, params  │
│ • Extract parameters with lowercase values            │
│ • Check against false positives whitelist             │
│ • Populate: paramValueLookup                          │
│ • Update UI progress bar                              │
└─────────────────────────────────────────────────────────┘
  ↓
[Check if user clicked Cancel]
  ↓
┌─────────────────────────────────────────────────────────┐
│ STEP 2: FIND REFLECTIONS (SINKS)                       │
│ • If paramValueLookup not empty, continue             │
│ • Iterate through all proxy history requests again    │
│ • ProxyFilterPotentialSink filters each request       │
│ • Criteria: HTTP method in sinkHTTPMethods, scope OK  │
│ • Split path by "/" and check each segment           │
│ • Match against paramValueLookup (case-insensitive)  │
│ • If match found: record as PotentialSink            │
│ • Populate: pathLookup                                │
│ • Update UI progress bar                              │
└─────────────────────────────────────────────────────────┘
  ↓
[Check if user clicked Cancel]
  ↓
┌─────────────────────────────────────────────────────────┐
│ RESULTS PROCESSING                                      │
│ • Print debug information to output                   │
│ • Display results in UI:                              │
│   - Left panel: reflected values                      │
│   - Right panel: associated sources & sinks          │
│ • Allow user interactions:                            │
│   - Copy URL with canary                             │
│   - Mark as false positive                           │
│   - Send sinks to Organizer                          │
└─────────────────────────────────────────────────────────┘
  ↓
END
```

---

## 💡 Contoh Skenario Nyata

### **Skenario: Menemukan CSPT di E-commerce**

```
┌─ Proxy History ─────────────────────────────────────────────┐
│                                                             │
│ REQUEST #1 (Source):                                       │
│ GET /products?search=laptop&category=electronics HTTP/1.1 │
│ Host: shop.example.com                                    │
│ Response: 200 OK, text/html                              │
│ Body: "Search results for laptop..."                     │
│                                                             │
│ REQUEST #2 (Sink - MATCH!):                              │
│ GET /download/laptop/invoice.pdf HTTP/1.1                │
│ Host: shop.example.com                                   │
│ Response: 200 OK                                         │
│                                                             │
│ REQUEST #3 (Sink - MATCH!):                              │
│ POST /api/export/laptop HTTP/1.1                         │
│ Host: shop.example.com                                   │
│ Response: 200 OK                                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘

ALGORITMA MENDETEKSI:

STEP 1 - SOURCE:
  Input: REQUEST #1
  Process:
    ✓ Method = GET
    ✓ MIME = text/html
    ✓ Status = 200 (< 400)
    ✓ Has params: search, category
    ✓ Not false positive
  Output:
    paramValueLookup["laptop"] = PotentialSource(
        paramName="search",
        paramValue="laptop",
        sourceURL="https://shop.example.com/products?search=laptop&category=electronics"
    )

STEP 2 - SINK:
  Input: REQUEST #2
  Process:
    ✓ Method = GET (dalam sinkHTTPMethods)
    ✓ URL matches sinkScope
    ✗ Path segments: ["download", "laptop", "invoice.pdf"]
    ✓ "laptop" ada dalam paramValueLookup
    → MATCH FOUND!
  Output:
    pathLookup["laptop"] = PotentialSink(
        method="GET",
        url="https://shop.example.com/download/laptop/invoice.pdf"
    )

  Input: REQUEST #3
  Process:
    ✓ Method = POST (dalam sinkHTTPMethods)
    ✓ URL matches sinkScope
    ✓ Path segments: ["api", "export", "laptop"]
    ✓ "laptop" ada dalam paramValueLookup
    → MATCH FOUND!
  Output:
    pathLookup["laptop"] = [
        PotentialSink(GET, .../download/laptop/invoice.pdf),
        PotentialSink(POST, .../api/export/laptop)
    ]

VULNERABILITY DETECTED:
  Reflected Value: "laptop"
  Sources: 1 (search parameter at /products)
  Sinks: 2 (GET /download/laptop/invoice.pdf, POST /api/export/laptop)
```

---

## 🎯 Best Practices untuk Menghindari False Positives

### **1. Konfigurasi Scope dengan Spesifik**

```
❌ BAD (Terlalu luas):
   sourceScope = ".*"
   sinkScope = ".*"

✅ GOOD (Spesifik):
   sourceScope = "https://myapp\.com/(products|search|catalog).*"
   sinkScope = "https://myapp\.com/(download|export|api).*"
```

### **2. Exclude Static Assets & CDN**

```
❌ Hasil: banyak false positives dari file statis

✅ Solusi: Tambah false positive rules:
   Parameter: "any"
   URL Pattern: ".*\.cdn\..*|.*static\..*|.*assets\..*"
```

### **3. Gunakan Canary Verification**

```
❌ Hanya percaya hasil automatic scan

✅ Langkah:
   1. Copy URL with canary untuk setiap finding
   2. Buka di browser
   3. Verifikasi canary token ada di sink path
   4. Hanya mark sebagai real vulnerability jika canary match
```

### **4. Review False Positive List Regularly**

```
❌ Set & lupa whitelist

✅ Maintenance:
   • Review setiap minggu
   • Evaluasi apakah rules masih relevan
   • Update regex patterns jika ada perubahan aplikasi
```

### **5. Combine dengan Manual Testing**

```
❌ 100% rely pada scan otomatis

✅ Hybrid approach:
   • Gunakan scan otomatis untuk deteksi awal
   • Manual test dengan custom payload
   • Verify dengan browser console untuk DOM manipulation
```

---

## 📈 Performance Considerations

```
Complexity Analysis:

Step 1 (Sources):     O(n × m)
  n = number of requests in proxy history
  m = average parameters per request
  
Step 2 (Sinks):       O(n × k × p)
  n = number of requests in proxy history
  k = average path segments
  p = size of paramValueLookup

Overall:              O(n²) worst case
  Dengan n = 10,000 requests
  Expected scan time = beberapa detik hingga menit
```

### Optimasi:
- Background scanning dengan `SwingWorker` (tidak block UI)
- Progress update setiap 100 requests
- Cancel support untuk long-running scans
- Case-insensitive comparison (efficient string matching)

---

## 🔒 Security Notes

- **Canary tokens**: Random 12-character ASCII strings (strong enough untuk testing)
- **Data persistence**: Disimpan di project file Burp (encrypted)
- **No external calls**: Scan terjadi lokal di proxy history
- **Memory safe**: Java's memory management

---

## 📝 Summary

| Aspek | Detail |
|-------|--------|
| **Apa dideteksi** | Parameter GET yang di-reflect di path URL request lain |
| **Pattern** | Exact string matching pada path segments (case-insensitive) |
| **False Positive Prevention** | Whitelist, scope filtering, HTTP method filtering, canary verification |
| **Key Classes** | `ProxyFilterPotentialSource`, `ProxyFilterPotentialSink`, `ClientSidePathTraversal` |
| **Data Structures** | `paramValueLookup` (sources), `pathLookup` (sinks) |
| **Verification Method** | Canary token injection & passive scan detection |
