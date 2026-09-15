/*
 * Test-only digest signing library for signtool /dlib.
 *
 * The metadata file passed with /dmdf holds key=value lines:
 *   key=<path to an unencrypted PKCS #8 DER RSA private key>
 *   fail=<HRESULT in hex>   optional; returns that HRESULT without signing
 *   log=<path>              optional; appends the last stage reached and its code
 *
 * The key is imported as an unnamed, ephemeral CNG key and never reaches a key store.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ncrypt.lib")

static void CopyValue(const char *text, DWORD length, const char *name, char *out, size_t outSize)
{
    size_t nameLength = strlen(name);
    DWORD i = 0;
    out[0] = '\0';
    while (i < length) {
        DWORD lineStart = i;
        while (i < length && text[i] != '\n' && text[i] != '\r') {
            i++;
        }
        DWORD lineLength = i - lineStart;
        if (lineLength > nameLength && text[lineStart + nameLength] == '=' &&
            strncmp(text + lineStart, name, nameLength) == 0) {
            size_t valueLength = lineLength - nameLength - 1;
            if (valueLength >= outSize) {
                valueLength = outSize - 1;
            }
            memcpy(out, text + lineStart + nameLength + 1, valueLength);
            out[valueLength] = '\0';
            return;
        }
        while (i < length && (text[i] == '\n' || text[i] == '\r')) {
            i++;
        }
    }
}

static LPCWSTR HashAlgorithmName(ALG_ID digestAlgId)
{
    switch (digestAlgId) {
    case CALG_SHA1: return BCRYPT_SHA1_ALGORITHM;
    case CALG_SHA_256: return BCRYPT_SHA256_ALGORITHM;
    case CALG_SHA_384: return BCRYPT_SHA384_ALGORITHM;
    case CALG_SHA_512: return BCRYPT_SHA512_ALGORITHM;
    default: return NULL;
    }
}

static HRESULT LastErrorResult(void)
{
    DWORD error = GetLastError();
    if (error == 0) {
        return E_FAIL;
    }
    return (error & 0x80000000) ? (HRESULT)error : HRESULT_FROM_WIN32(error);
}

static void LogStage(const char *logPath, const char *stage, HRESULT code, ALG_ID digestAlgId, DWORD digestSize)
{
    if (logPath[0] == '\0') {
        return;
    }
    HANDLE log = CreateFileA(logPath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
    if (log == INVALID_HANDLE_VALUE) {
        return;
    }
    char line[256];
    int length = sprintf_s(line, sizeof(line), "%s 0x%08lX alg=0x%04lX digest=%lu\r\n", stage, (unsigned long)code, (unsigned long)digestAlgId, (unsigned long)digestSize);
    if (length > 0) {
        DWORD written = 0;
        WriteFile(log, line, (DWORD)length, &written, NULL);
    }
    CloseHandle(log);
}

HRESULT WINAPI AuthenticodeDigestSign(
    PCCERT_CONTEXT pSigningCert,
    PCRYPT_DATA_BLOB pMetadataBlob,
    ALG_ID digestAlgId,
    PBYTE pbToBeSignedDigest,
    DWORD cbToBeSignedDigest,
    PCRYPT_DATA_BLOB pSignedDigest)
{
    char keyPath[MAX_PATH] = { 0 };
    char fail[32] = { 0 };
    char logPath[MAX_PATH] = { 0 };
    WCHAR wideKeyPath[MAX_PATH] = { 0 };
    HANDLE file = INVALID_HANDLE_VALUE;
    BYTE *keyBytes = NULL;
    DWORD size = 0;
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    HRESULT result = E_FAIL;
    const char *stage = "arguments";

    UNREFERENCED_PARAMETER(pSigningCert);

    if (pMetadataBlob == NULL || pMetadataBlob->pbData == NULL || pSignedDigest == NULL) {
        return E_INVALIDARG;
    }

    CopyValue((const char *)pMetadataBlob->pbData, pMetadataBlob->cbData, "log", logPath, sizeof(logPath));
    CopyValue((const char *)pMetadataBlob->pbData, pMetadataBlob->cbData, "fail", fail, sizeof(fail));
    if (fail[0] != '\0') {
        result = (HRESULT)strtoul(fail, NULL, 16);
        LogStage(logPath, "fail-requested", result, digestAlgId, cbToBeSignedDigest);
        return result;
    }
    CopyValue((const char *)pMetadataBlob->pbData, pMetadataBlob->cbData, "key", keyPath, sizeof(keyPath));
    MultiByteToWideChar(CP_UTF8, 0, keyPath, -1, wideKeyPath, MAX_PATH);

    stage = "digest-algorithm";
    LPCWSTR hashName = HashAlgorithmName(digestAlgId);
    if (hashName == NULL) {
        result = NTE_BAD_ALGID;
        goto cleanup;
    }

    stage = "open-key-file";
    file = CreateFileW(wideKeyPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        result = LastErrorResult();
        goto cleanup;
    }
    size = GetFileSize(file, NULL);
    keyBytes = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
    DWORD read = 0;
    stage = "read-key-file";
    if (keyBytes == NULL || !ReadFile(file, keyBytes, size, &read, NULL) || read != size) {
        result = keyBytes == NULL ? E_OUTOFMEMORY : LastErrorResult();
        goto cleanup;
    }

    stage = "open-provider";
    SECURITY_STATUS status = NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0);
    if (status != ERROR_SUCCESS) {
        result = status;
        goto cleanup;
    }

    stage = "import-key";
    status = NCryptImportKey(provider, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &key, keyBytes, size, NCRYPT_SILENT_FLAG);
    if (status != ERROR_SUCCESS) {
        result = status;
        goto cleanup;
    }

    stage = "sign-size";
    BCRYPT_PKCS1_PADDING_INFO padding = { hashName };
    DWORD signatureSize = 0;
    status = NCryptSignHash(key, &padding, pbToBeSignedDigest, cbToBeSignedDigest, NULL, 0, &signatureSize, BCRYPT_PAD_PKCS1);
    if (status != ERROR_SUCCESS) {
        result = status;
        goto cleanup;
    }
    pSignedDigest->pbData = (BYTE *)HeapAlloc(GetProcessHeap(), 0, signatureSize);
    if (pSignedDigest->pbData == NULL) {
        result = E_OUTOFMEMORY;
        goto cleanup;
    }
    stage = "sign";
    status = NCryptSignHash(key, &padding, pbToBeSignedDigest, cbToBeSignedDigest, pSignedDigest->pbData, signatureSize, &signatureSize, BCRYPT_PAD_PKCS1);
    if (status != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, pSignedDigest->pbData);
        pSignedDigest->pbData = NULL;
        result = status;
        goto cleanup;
    }
    pSignedDigest->cbData = signatureSize;
    stage = "done";
    result = S_OK;

cleanup:
    LogStage(logPath, stage, result, digestAlgId, cbToBeSignedDigest);
    if (key != 0) {
        NCryptFreeObject(key);
    }
    if (provider != 0) {
        NCryptFreeObject(provider);
    }
    if (keyBytes != NULL) {
        SecureZeroMemory(keyBytes, size);
        HeapFree(GetProcessHeap(), 0, keyBytes);
    }
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    return result;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(reserved);
    return TRUE;
}
