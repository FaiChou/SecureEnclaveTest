import Foundation
import Security
import LocalAuthentication

class SecureEnclaveManager {
    static let shared = SecureEnclaveManager()
    private let tag = "com.faichou.encryption.key".data(using: .utf8)!
    
    private init() {}
    
    func generateAndStoreKey() async throws -> SecKey {
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage, .userPresence]
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            nil
        ) else {
            throw NSError(domain: "SecureEnclaveManager", code: -1, userInfo: [NSLocalizedDescriptionKey: "无法创建访问控制"])
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error?.takeRetainedValue() ?? NSError(domain: "SecureEnclaveManager", code: -1)
        }
        
        return privateKey
    }
    
    func retrieveKey() async throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            throw NSError(domain: "SecureEnclaveManager", code: -1, userInfo: [NSLocalizedDescriptionKey: "未找到密钥"])
        }
        
        return item as! SecKey
    }
    
    func encrypt(_ data: Data, with publicKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(
            publicKey,
            .eciesEncryptionStandardX963SHA256AESGCM,
            data as CFData,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() ?? NSError(domain: "SecureEnclaveManager", code: -1)
        }
        return encryptedData
    }
    
    func decrypt(_ encryptedData: Data, with privateKey: SecKey) async throws -> Data {
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(
            privateKey,
            .eciesEncryptionStandardX963SHA256AESGCM,
            encryptedData as CFData,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() ?? NSError(domain: "SecureEnclaveManager", code: -1)
        }
        return decryptedData
    }
} 
