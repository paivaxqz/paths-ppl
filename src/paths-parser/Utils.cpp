#include "Include.h"
#include "Replaceparser.h"
#include <cstring>

static std::wstring utf8_to_wstring(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring ws(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &ws[0], len);
    return ws;
}

static std::string wstring_to_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
}

inline std::string replaceParserDir;
inline std::unordered_map<std::string, std::vector<ReplacementEntry>> replacementCache;
static std::map<std::pair<std::string, std::string>, ReplacementEntry> gLatestResults;

std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

bool isDllFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return false;
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (!file || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;
    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    uint32_t peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));
    if (!file || peSignature != IMAGE_NT_SIGNATURE) return false;
    IMAGE_FILE_HEADER fileHeader;
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
    if (!file) return false;
    return (fileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}

bool WriteExeToTemp(const std::string& replaceParserDir) {
    std::string exePath = replaceParserDir + "\\replaceparser.exe";
    std::ofstream exeFile(exePath, std::ios::binary);
    if (!exeFile) {
        std::cerr << "Failed to create executable file: " << exePath << std::endl;
        return false;
    }
    exeFile.write(reinterpret_cast<const char*>(ReplaceParserHex), sizeof(ReplaceParserHex));
    exeFile.close();
    return true;
}

bool DeleteReplaceParserDir(const std::string& replaceParserDir) {
    try {
        std::filesystem::remove_all(replaceParserDir);
        return true;
    }
    catch (const std::filesystem::filesystem_error&) {
        return false;
    }
}

bool ExecuteReplaceParser(const std::string& replaceParserDir) {
    std::string exePath = replaceParserDir + "\\replaceparser.exe";
    std::string replacesTxtPath = replaceParserDir + "\\replaces.txt";
    std::string commandLine = "\"" + exePath + "\" \"" + replacesTxtPath + "\"";
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    HANDLE hNull = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hNull == INVALID_HANDLE_VALUE) return false;
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdOutput = hNull;
    si.hStdError = hNull;
    if (!CreateProcessA(NULL, const_cast<char*>(commandLine.c_str()), NULL, NULL, TRUE, 0, NULL, replaceParserDir.c_str(), &si, &pi)) {
        CloseHandle(hNull);
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hNull);
    return true;
}

void PreProcessReplacements(const std::string& logFilePath) {
    std::ifstream file(logFilePath);
    if (!file.is_open()) return;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        std::string replaceType, pattern;
        if (line.rfind("Explorer replacement found in file: ", 0) == 0) {
            replaceType = "Explorer";
            pattern = "Explorer replacement found in file: ";
        }
        else if (line.rfind("Copy replacement found in file: ", 0) == 0) {
            replaceType = "Copy";
            pattern = "Copy replacement found in file: ";
        }
        else if (line.rfind("Type pattern found in file: ", 0) == 0) {
            replaceType = "Type";
            pattern = "Type pattern found in file: ";
        }
        else if (line.rfind("Delete pattern found in file: ", 0) == 0) {
            replaceType = "Delete";
            pattern = "Delete pattern found in file: ";
        }
        else {
            continue;
        }
        size_t pos = line.find(pattern);
        if (pos == std::string::npos) continue;
        std::string foundFileName = line.substr(pos + pattern.size());
        std::string foundFileNameLower = ToLower(foundFileName);
        bool openBraceFound = false;
        std::string detailsCollected, detailsLine;
        while (std::getline(file, detailsLine)) {
            if (!openBraceFound) {
                size_t bracePos = detailsLine.find('{');
                if (bracePos != std::string::npos) {
                    openBraceFound = true;
                    if (bracePos + 1 < detailsLine.size())
                        detailsCollected += detailsLine.substr(bracePos + 1) + "\n";
                }
            }
            else {
                size_t closePos = detailsLine.find('}');
                if (closePos != std::string::npos) {
                    if (closePos > 0)
                        detailsCollected += detailsLine.substr(0, closePos);
                    break;
                }
                else {
                    detailsCollected += detailsLine + "\n";
                }
            }
        }
        ReplacementEntry entry = { foundFileName, replaceType, detailsCollected };
        replacementCache[foundFileNameLower].push_back(entry);
    }
}

void FindReplace(const std::string& inputFileName) {
    std::string key = ToLower(inputFileName);
    auto it = replacementCache.find(key);
    if (it != replacementCache.end()) {
        for (auto& entry : it->second) {
            gLatestResults[{ entry.fileName, entry.replaceType }] = entry;
        }
    }
}

void WriteAllReplacementsToFileAndPrintSummary() {
    if (gLatestResults.empty()) {
        std::cout << "\n\nNo replacements found." << std::endl;
        return;
    }
    std::string outputFileName = "replaces.txt";
    std::ofstream outFile(outputFileName);
    for (auto& kv : gLatestResults) {
        outFile << "Found replacement type: " << kv.second.replaceType << "\n";
        outFile << "In file: " << kv.second.fileName << "\n";
        outFile << "Replacement details:\n" << kv.second.details << "\n\n";
    }
    outFile.close();
    std::cout << "\n\nFound " << gLatestResults.size() << " possible replacements, check " << outputFileName << std::endl;
    std::string cmd = "start \"\" \"" + outputFileName + "\"";
    std::system(cmd.c_str());
}

bool initReplaceParser() {
    wchar_t tmp[MAX_PATH];
    DWORD len = GetTempPathW(MAX_PATH, tmp);
    if (len == 0 || len > MAX_PATH) {
        std::cerr << "Failed to get temporary directory." << std::endl;
        return false;
    }
    std::wstring wtemp(tmp, tmp + len);
    if (!wtemp.empty() && (wtemp.back() == L'\\' || wtemp.back() == L'/'))
        wtemp.pop_back();
    replaceParserDir = wstring_to_utf8(wtemp) + "\\replaceparser";
    auto wdir = utf8_to_wstring(replaceParserDir);
    if (!CreateDirectoryW(wdir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        std::cerr << "Failed to create directory: " << replaceParserDir << std::endl;
        return false;
    }
    if (!WriteExeToTemp(replaceParserDir) || !ExecuteReplaceParser(replaceParserDir))
        return false;
    return true;
}

bool DestroyReplaceParser() {
    if (!DeleteReplaceParserDir(replaceParserDir)) {
        std::cerr << "There was a problem deleting the replaceparser folder." << std::endl;
        return false;
    }
    return true;
}

__int64 privilege(const char* priv) {
    HANDLE thandle;
    LUID identifier;
    TOKEN_PRIVILEGES privileges{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &thandle)) {
        std::cerr << "OpenProcessToken error: " << GetLastError() << std::endl;
        return 0;
    }
    if (!LookupPrivilegeValueA(nullptr, priv, &identifier)) {
        std::cerr << "LookupPrivilegeValueA error: " << GetLastError() << std::endl;
        CloseHandle(thandle);
        return 0;
    }
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = identifier;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(thandle, FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
        std::cerr << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
        CloseHandle(thandle);
        return 0;
    }
    DWORD error = GetLastError();
    if (error == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "privileges error at assign." << std::endl;
        CloseHandle(thandle);
        return 0;
    }
    CloseHandle(thandle);
    return 1;
}

bool file_exists(const std::string& path) {
    auto wpath = utf8_to_wstring(path);
    return GetFileAttributesW(wpath.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::string getOwnPath() {
    wchar_t buffer[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, buffer, MAX_PATH);
    return wstring_to_utf8(std::wstring(buffer, buffer + len));
}

bool iequals(const std::string& a, const std::string& b) {
    return a.size() == b.size() &&
        std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) { return tolower(x) == tolower(y); });
}

// SHA-1 of genuine Microsoft root CAs. "Signed" + subject contains Microsoft Corp. but root not listed => local spoof CA.
static bool Sha1EqualsKnownMicrosoftRoot(const BYTE* sha1, size_t len) {
    if (len != 20 || !sha1) return false;
    static const BYTE kMsRoot2010[20] = {
        0x3B, 0x1E, 0xFD, 0x3A, 0x66, 0xEA, 0x28, 0xB1, 0x66, 0x97, 0x39, 0x47, 0x03, 0xA7, 0x2C, 0xA3, 0x40, 0xA0, 0x5B, 0xD5
    };
    static const BYTE kMsRoot2011[20] = {
        0x8F, 0x43, 0x28, 0x8A, 0xD2, 0x72, 0xF3, 0x10, 0x3B, 0x6F, 0xB1, 0x42, 0x84, 0x85, 0xEA, 0x30, 0x14, 0xC0, 0xBC, 0xFE
    };
    static const BYTE kMsRootAuthorityLegacy[20] = {
        0xA4, 0x34, 0x89, 0x15, 0x9A, 0x52, 0x0F, 0x0D, 0x93, 0xD0, 0x32, 0xCC, 0xAF, 0x37, 0xE7, 0xFE, 0x20, 0xA8, 0xB4, 0x19
    };
    static const BYTE kMsRootCaDc[20] = {
        0xCD, 0xD4, 0xEE, 0xAE, 0x60, 0x00, 0xAC, 0x7F, 0x40, 0xC3, 0x80, 0x2C, 0x17, 0x1E, 0x30, 0x14, 0x80, 0x30, 0xC0, 0x72
    };
    static const BYTE kMsAuthenticodeRoot[20] = {
        0x7F, 0x88, 0xCD, 0x72, 0x23, 0xF3, 0xC8, 0x13, 0x81, 0x8C, 0x99, 0x46, 0x14, 0xA8, 0x9C, 0x99, 0xFA, 0x3B, 0x52, 0x47
    };
    static const BYTE kMsIdentityRoot2020[20] = {
        0xF4, 0x00, 0x42, 0xE2, 0xE5, 0xF7, 0xE8, 0xEF, 0x81, 0x89, 0xFE, 0xD1, 0x55, 0x19, 0xAE, 0xCE, 0x42, 0xC3, 0xBF, 0xA2
    };
    static const BYTE kMsEccProductRoot2018[20] = {
        0x06, 0xF1, 0xAA, 0x33, 0x0B, 0x92, 0x7B, 0x75, 0x3A, 0x40, 0xE6, 0x8C, 0xDF, 0x22, 0xE3, 0x4B, 0xCB, 0xEF, 0x33, 0x52
    };
    static const BYTE kMsEccTsRoot2018[20] = {
        0x31, 0xF9, 0xFC, 0x8B, 0xA3, 0x80, 0x59, 0x86, 0xB7, 0x21, 0xEA, 0x72, 0x95, 0xC6, 0x5B, 0x3A, 0x44, 0x53, 0x42, 0x74
    };
    static const BYTE kMsTimeStampRoot2014[20] = {
        0x01, 0x19, 0xE8, 0x1B, 0xE9, 0xA1, 0x4C, 0xD8, 0xE2, 0x2F, 0x40, 0xAC, 0x11, 0x8C, 0x68, 0x7E, 0xCB, 0xA3, 0xF4, 0xD8
    };
    static const BYTE kMsTimeStampingServiceRoot[20] = {
        0x24, 0x5C, 0x97, 0xDF, 0x75, 0x14, 0xE7, 0xCF, 0x2D, 0xF8, 0xBE, 0x72, 0xAE, 0x95, 0x7B, 0x9E, 0x04, 0x74, 0x1E, 0x85
    };
    const BYTE* roots[] = {
        kMsRoot2010, kMsRoot2011, kMsRootAuthorityLegacy, kMsRootCaDc,
        kMsAuthenticodeRoot, kMsIdentityRoot2020, kMsEccProductRoot2018,
        kMsEccTsRoot2018, kMsTimeStampRoot2014, kMsTimeStampingServiceRoot
    };
    for (const BYTE* r : roots) {
        if (std::memcmp(sha1, r, 20) == 0) return true;
    }
    return false;
}

static bool GetChainRootSha1(PCCERT_CONTEXT pSigner, std::vector<BYTE>& outSha1) {
    CERT_CHAIN_PARA chainPara = {};
    chainPara.cbSize = sizeof(chainPara);
    PCCERT_CHAIN_CONTEXT pChainContext = nullptr;
    if (!CertGetCertificateChain(nullptr, pSigner, nullptr, nullptr, &chainPara, 0, nullptr, &pChainContext))
        return false;
    if (!pChainContext || pChainContext->cChain == 0 || !pChainContext->rgpChain[0]) {
        if (pChainContext) CertFreeCertificateChain(pChainContext);
        return false;
    }
    PCERT_SIMPLE_CHAIN pSimple = pChainContext->rgpChain[0];
    if (pSimple->cElement == 0) {
        CertFreeCertificateChain(pChainContext);
        return false;
    }
    PCCERT_CONTEXT pRoot = pSimple->rgpElement[pSimple->cElement - 1]->pCertContext;
    DWORD hashLen = 0;
    if (!CertGetCertificateContextProperty(pRoot, CERT_SHA1_HASH_PROP_ID, nullptr, &hashLen)) {
        CertFreeCertificateChain(pChainContext);
        return false;
    }
    outSha1.resize(hashLen);
    if (!CertGetCertificateContextProperty(pRoot, CERT_SHA1_HASH_PROP_ID, outSha1.data(), &hashLen)) {
        CertFreeCertificateChain(pChainContext);
        return false;
    }
    CertFreeCertificateChain(pChainContext);
    return true;
}

static bool VerifyFileViaCatalog(LPCWSTR filePath) {
    HANDLE hCatAdmin = NULL;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
        return false;
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }
    DWORD dwHashSize = 0;
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0)) {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }
    BYTE* pbHash = new BYTE[dwHashSize];
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash, 0)) {
        delete[] pbHash;
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }
    CloseHandle(hFile);
    CATALOG_INFO catInfo = { 0 };
    catInfo.cbStruct = sizeof(catInfo);
    HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, NULL);
    bool isCatalogSigned = false;
    while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
        WINTRUST_CATALOG_INFO wtc = {};
        wtc.cbStruct = sizeof(wtc);
        wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
        wtc.pbCalculatedFileHash = pbHash;
        wtc.cbCalculatedFileHash = dwHashSize;
        wtc.pcwszMemberFilePath = filePath;
        WINTRUST_DATA wtd = {};
        wtd.cbStruct = sizeof(wtd);
        wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wtd.pCatalog = &wtc;
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;
        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG res = WinVerifyTrust(NULL, &action, &wtd);
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wtd);
        if (res == ERROR_SUCCESS) {
            isCatalogSigned = true;
            break;
        }
        hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, &hCatInfo);
    }
    if (hCatInfo)
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    CryptCATAdminReleaseContext(hCatAdmin, 0);
    delete[] pbHash;
    return isCatalogSigned;
}

std::string getDigitalSignature(const std::string& filePath) {
    auto wpath = utf8_to_wstring(filePath);
    if (GetFileAttributesW(wpath.c_str()) == INVALID_FILE_ATTRIBUTES)
        return "Not signed";
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wpath.c_str();
    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.pFile = &fileInfo;
    LONG status = WinVerifyTrust(NULL, &guidAction, &winTrustData);
    std::string result = (status == ERROR_SUCCESS) ? "Signed" : "Not signed";
    if (status == ERROR_SUCCESS) {
        auto pProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
        if (pProvData) {
            auto nonConst = const_cast<CRYPT_PROVIDER_DATA*>(pProvData);
            auto pProvSigner = WTHelperGetProvSignerFromChain(nonConst, 0, FALSE, 0);
            if (pProvSigner) {
                auto pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
                if (pProvCert && pProvCert->pCert) {
                    PCCERT_CONTEXT signingCert = pProvCert->pCert;
                    std::string subjLower;
                    char subjName[256] = {};
                    if (CertNameToStrA(
                        signingCert->dwCertEncodingType,
                        &signingCert->pCertInfo->Subject,
                        CERT_X500_NAME_STR,
                        subjName,
                        sizeof(subjName)) > 1) {
                        subjLower.assign(subjName);
                        std::transform(subjLower.begin(), subjLower.end(), subjLower.begin(), ::tolower);
                        static const char* cheats[] = {
                            "manthe industries, llc",
                            "slinkware",
                            "amstion limited",
                            "55.604.504 rafael ferreira de carvalho"
                        };
                        for (auto c : cheats) {
                            if (subjLower.find(c) != std::string::npos) {
                                result = "Cheat Signature";
                                break;
                            }
                        }
                    }
                    DWORD hashLen = 0;
                    if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, nullptr, &hashLen)) {
                        std::vector<BYTE> hash(hashLen);
                        if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, hash.data(), &hashLen)) {
                            CRYPT_HASH_BLOB blob = { hashLen, hash.data() };
                            static const LPCWSTR storeNames[] = {
                                L"MY", L"Root", L"Trust", L"CA", L"UserDS",
                                L"TrustedPublisher", L"Disallowed", L"AuthRoot",
                                L"TrustedPeople", L"ClientAuthIssuer",
                                L"CertificateEnrollment", L"SmartCardRoot"
                            };
                            const DWORD contexts[] = {
                                CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
                                CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG
                            };
                            bool foundAnywhere = false;
                            for (DWORD ctx : contexts) {
                                for (auto storeName : storeNames) {
                                    HCERTSTORE hStore = CertOpenStore(
                                        CERT_STORE_PROV_SYSTEM_W,
                                        0,
                                        NULL,
                                        ctx,
                                        storeName
                                    );
                                    if (!hStore) continue;
                                    PCCERT_CONTEXT foundContext = CertFindCertificateInStore(
                                        hStore,
                                        signingCert->dwCertEncodingType,
                                        0,
                                        CERT_FIND_SHA1_HASH,
                                        &blob,
                                        NULL
                                    );
                                    if (foundContext) {
                                        foundAnywhere = true;
                                        CertFreeCertificateContext(foundContext);
                                    }
                                    CertCloseStore(hStore, 0);
                                    if (foundAnywhere) break;
                                }
                                if (foundAnywhere) break;
                            }
                            if (foundAnywhere) {
                                result = "Fake Signature";
                            }
                        }
                    }
                    if (result == "Signed" && !subjLower.empty() &&
                        subjLower.find("microsoft corporation") != std::string::npos) {
                        std::vector<BYTE> rootSha1;
                        if (GetChainRootSha1(signingCert, rootSha1) &&
                            !Sha1EqualsKnownMicrosoftRoot(rootSha1.data(), rootSha1.size())) {
                            result = "te peguei bobo";
                        }
                    }
                }
            }
        }
    }
    else {
        if (VerifyFileViaCatalog(wpath.c_str())) {
            result = "Signed";
        }
    }
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &winTrustData);
    return result;
}

bool isMZFile(const std::string& path) {
    auto wpath = utf8_to_wstring(path);
    HANDLE hFile = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    WORD mzHeader;
    DWORD bytesRead;
    bool result = ReadFile(hFile, &mzHeader, sizeof(mzHeader), &bytesRead, NULL) &&
        bytesRead == sizeof(mzHeader) &&
        mzHeader == 0x5A4D;
    CloseHandle(hFile);
    return result;
}

void checkPEAnomalies(const std::string& path, std::vector<std::string>& alerts) {
    auto wpath = utf8_to_wstring(path);
    HANDLE hFile = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    FILETIME ftCreation, ftLastAccess, ftLastWrite;
    if (!GetFileTime(hFile, &ftCreation, &ftLastAccess, &ftLastWrite)) {
        CloseHandle(hFile);
        return;
    }

    ULARGE_INTEGER ulCreation, ulLastWrite;
    ulCreation.LowPart = ftCreation.dwLowDateTime;
    ulCreation.HighPart = ftCreation.dwHighDateTime;
    ulLastWrite.LowPart = ftLastWrite.dwLowDateTime;
    ulLastWrite.HighPart = ftLastWrite.dwHighDateTime;

    uint64_t ntfsCreationSec = (ulCreation.QuadPart >= 116444736000000000ULL) ?
        (ulCreation.QuadPart - 116444736000000000ULL) / 10000000ULL : 0;
    uint64_t ntfsWriteSec = (ulLastWrite.QuadPart >= 116444736000000000ULL) ?
        (ulLastWrite.QuadPart - 116444736000000000ULL) / 10000000ULL : 0;

    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    ULARGE_INTEGER ulNow;
    ulNow.LowPart = ftNow.dwLowDateTime;
    ulNow.HighPart = ftNow.dwHighDateTime;
    uint64_t nowSec = (ulNow.QuadPart >= 116444736000000000ULL) ?
        (ulNow.QuadPart - 116444736000000000ULL) / 10000000ULL : 0;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32)) {
        CloseHandle(hFile);
        return;
    }

    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) || bytesRead != sizeof(dosHeader)) {
        CloseHandle(hFile);
        return;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0 ||
        dosHeader.e_lfanew > fileSize.QuadPart - sizeof(IMAGE_NT_HEADERS32)) {
        CloseHandle(hFile);
        return;
    }

    if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(hFile);
        return;
    }

    DWORD ntSignature = 0;
    if (!ReadFile(hFile, &ntSignature, sizeof(ntSignature), &bytesRead, NULL) || ntSignature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        return;
    }

    IMAGE_FILE_HEADER fileHeader;
    if (!ReadFile(hFile, &fileHeader, sizeof(fileHeader), &bytesRead, NULL) || bytesRead != sizeof(fileHeader)) {
        CloseHandle(hFile);
        return;
    }

    DWORD peTime = fileHeader.TimeDateStamp;
    if (peTime > 0) {
        if (ntfsCreationSec > 0 && ntfsWriteSec > 0 &&
            (ntfsCreationSec + 86400 < peTime) && (ntfsWriteSec + 86400 < peTime)) {
            alerts.push_back("Timestomp Detected");
        }
        else if (nowSec > 0 && peTime > nowSec + 86400) {
            alerts.push_back("PE Future Timestamp");
        }
        else if (peTime < 946684800) {
            alerts.push_back("PE Wiped Timestamp");
        }
    }

    DWORD importRva = 0;
    DWORD importSize = 0;
    if (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        IMAGE_OPTIONAL_HEADER64 optHeader;
        if (ReadFile(hFile, &optHeader, sizeof(optHeader), &bytesRead, NULL) && bytesRead == sizeof(optHeader)) {
            importRva = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            importSize = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
    }
    else if (fileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        IMAGE_OPTIONAL_HEADER32 optHeader;
        if (ReadFile(hFile, &optHeader, sizeof(optHeader), &bytesRead, NULL) && bytesRead == sizeof(optHeader)) {
            importRva = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            importSize = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
    }

    if (fileSize.QuadPart > 80 * 1024) {
        if (importRva == 0 || importSize == 0) {
            alerts.push_back("No IAT / Stripped Imports");
        }
        else if (importSize > 0 && importSize <= sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            alerts.push_back("Suspicious Tiny IAT");
        }
    }

    CloseHandle(hFile);
}

std::string getOwnDirectory() {
    std::string own = getOwnPath();
    std::wstring wown = utf8_to_wstring(own);
    size_t pos = wown.find_last_of(L"\\/");
    return wstring_to_utf8(wown.substr(0, pos + 1));
}

bool hasInvalidSemicolonPath(const std::string& str) {
    size_t pos = 0;
    while ((pos = str.find(';', pos)) != std::string::npos) {
        if (pos + 2 < str.size() && str.substr(pos + 2, 2) == ":\\") {
            return true;
        }
        pos++;
    }
    return false;
}

bool isValidPathToProcess(const std::string& path, bool searchfordll) {
    if (!path.empty() && path.back() == '\\' && !file_exists(path)) {
        return false;
    }
    if (hasInvalidSemicolonPath(path)) {
        return false;
    }
    if (searchfordll) {
        return isDllFile(path);
    }
    else {
        return true;
    }
}

std::string extractValidPath(const std::string& line) {
    size_t p = line.find(":\\"), p2 = p;
    if (p == std::string::npos) p2 = line.find(":/");
    if (p2 == std::string::npos || p2 == 0) return "";
    if (line.find_last_of(";", p2) != std::string::npos) return "";
    char dl = line[p2 - 1];
    if (!std::isalpha(dl)) return "";
    std::string path = line.substr(p2 - 1);
    std::replace(path.begin(), path.end(), '/', '\\');
    if (!isValidPathToProcess(path, scanForDLLsOnly)) return "";
    return path;
}
bool is_directory(const std::string& path) {
    DWORD attributes = GetFileAttributesA(path.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY));
}

std::string rtrim(const std::string& s) {
    size_t end = s.find_last_not_of(" \t");
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

std::vector<std::string> readPathsFromFile(const std::string& filePath) {
    std::vector<std::string> paths;
    std::unordered_set<std::string> uniquePaths;
    std::ifstream f(filePath);
    std::string line;
    while (std::getline(f, line)) {
        line = rtrim(line);
        std::string p = extractValidPath(line);
        if (!p.empty() && uniquePaths.insert(p).second) {
            paths.push_back(p);
        }
    }
    return paths;
}

std::vector<std::string> getAllTargetPaths() {
    std::vector<std::string> allPaths;
    std::vector<std::string> targetFiles = {
        "search results.txt",
        "paths.txt",
        "p.txt"
    };
    for (auto& fn : targetFiles) {
        std::string full = "C:\\" + fn;
        if (file_exists(full)) {
            std::cout << "Found and reading: " << full << std::endl;
            auto v = readPathsFromFile(full);
            allPaths.insert(allPaths.end(), v.begin(), v.end());
        }
    }
    std::string dir = getOwnDirectory();
    for (auto& fn : targetFiles) {
        std::string full = dir + fn;
        if (file_exists(full)) {
            std::cout << "Found and reading: " << full << std::endl;
            auto v = readPathsFromFile(full);
            allPaths.insert(allPaths.end(), v.begin(), v.end());
        }
    }
    return allPaths;
}
