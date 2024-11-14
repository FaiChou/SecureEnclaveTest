//
//  ContentView.swift
//  SecureEnclaveTest
//
//  Created by 周辉 on 2024/11/13.
//

import SwiftUI

struct ContentView: View {
    @State private var inputText = ""
    @State private var encryptedText = ""
    @State private var decryptedText = ""
    @State private var hasKey = false
    @State private var showError = false
    @State private var errorMessage = ""
    @State private var isLoading = false
    
    private let secureEnclaveManager = SecureEnclaveManager.shared
    @State private var currentKey: SecKey?
    
    var body: some View {
        VStack(spacing: 20) {
            TextField("请输入要加密的文本", text: $inputText)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
            
            Button("生成密钥") {
                Task {
                    await generateKey()
                }
            }
            .disabled(isLoading)
            
            Button("加密") {
                encrypt()
            }
            .disabled(!hasKey || isLoading)
            
            if !encryptedText.isEmpty {
                Text("加密结果：\n\(encryptedText)")
                    .multilineTextAlignment(.center)
                    .padding()
            }
            
            Button("解密") {
                Task {
                    await decrypt()
                }
            }
            .disabled(!hasKey || encryptedText.isEmpty || isLoading)
            
            if !decryptedText.isEmpty {
                Text("解密结果：\n\(decryptedText)")
                    .multilineTextAlignment(.center)
                    .padding()
            }
            
            if isLoading {
                ProgressView()
            }
        }
        .padding()
        .alert("错误", isPresented: $showError) {
            Button("确定", role: .cancel) {}
        } message: {
            Text(errorMessage)
        }
        .onAppear {
            Task {
                await checkExistingKey()
            }
        }
    }
    
    private func checkExistingKey() async {
        isLoading = true
        defer { isLoading = false }
        
        do {
            currentKey = try await secureEnclaveManager.retrieveKey()
            hasKey = true
        } catch {
            // 首次启动可能没有密钥，不需要显示错误
            print("No existing key found: \(error.localizedDescription)")
        }
    }
    
    private func generateKey() async {
        isLoading = true
        defer { isLoading = false }
        
        do {
            currentKey = try await secureEnclaveManager.generateAndStoreKey()
            hasKey = true
        } catch {
            errorMessage = "生成密钥失败：\(error.localizedDescription)"
            showError = true
        }
    }
    
    private func encrypt() {
        guard let key = currentKey,
              let publicKey = SecKeyCopyPublicKey(key) else {
            errorMessage = "获取公钥失败"
            showError = true
            return
        }
        
        guard !inputText.isEmpty else {
            errorMessage = "请输入要加密的文本"
            showError = true
            return
        }
        
        do {
            let data = inputText.data(using: .utf8)!
            let encryptedData = try secureEnclaveManager.encrypt(data, with: publicKey)
            encryptedText = encryptedData.base64EncodedString()
        } catch {
            errorMessage = "加密失败：\(error.localizedDescription)"
            showError = true
        }
    }
    
    private func decrypt() async {
        isLoading = true
        defer { isLoading = false }
        
        guard let key = currentKey else {
            errorMessage = "密钥不存在"
            showError = true
            return
        }
        
        do {
            guard let encryptedData = Data(base64Encoded: encryptedText) else {
                errorMessage = "无效的加密数据"
                showError = true
                return
            }
            
            let decryptedData = try await secureEnclaveManager.decrypt(encryptedData, with: key)
            decryptedText = String(data: decryptedData, encoding: .utf8) ?? ""
        } catch {
            errorMessage = "解密失败：\(error.localizedDescription)"
            showError = true
        }
    }
}

#Preview {
    ContentView()
}
