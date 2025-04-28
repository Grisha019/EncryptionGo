using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using EncryptionGo.Models;
using Microsoft.AspNetCore.Mvc;

// 🔥 Добавлены подключения библиотек для Bouncy Castle и Libsodium
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Sodium;

namespace EncryptionGo.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet]
        public IActionResult Index()
        {
            return View(new EncryptionViewModel { Algorithm = "AES" });
        }

        [HttpPost]
        public IActionResult Index(EncryptionViewModel model)
        {
            if (string.IsNullOrWhiteSpace(model.InputText)) return View(model);

            try
            {
                if (model.Algorithm == "AES") 
                {
                    using var aes = Aes.Create();

                    if (!string.IsNullOrEmpty(model.Key))
                        aes.Key = Convert.FromBase64String(model.Key);
                    else
                        model.Key = Convert.ToBase64String(aes.Key);

                    if (!string.IsNullOrEmpty(model.IV))
                        aes.IV = Convert.FromBase64String(model.IV);
                    else
                        model.IV = Convert.ToBase64String(aes.IV);

                    var plain = Encoding.UTF8.GetBytes(model.InputText);
                    using var encryptor = aes.CreateEncryptor();
                    var encrypted = encryptor.TransformFinalBlock(plain, 0, plain.Length);
                    model.EncryptedText = Convert.ToBase64String(encrypted);

                    using var decryptor = aes.CreateDecryptor();
                    var decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
                    model.DecryptedText = Encoding.UTF8.GetString(decrypted);
                }
                else if (model.Algorithm == "RSA") 
                {
                    using var rsa = RSA.Create(2048);

                    if (string.IsNullOrEmpty(model.PublicKey) || string.IsNullOrEmpty(model.PrivateKey))
                    {
                        model.PublicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                        model.PrivateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                    }
                    else
                    {
                        rsa.ImportRSAPublicKey(Convert.FromBase64String(model.PublicKey), out _);
                        rsa.ImportRSAPrivateKey(Convert.FromBase64String(model.PrivateKey), out _);
                    }

                    var plain = Encoding.UTF8.GetBytes(model.InputText);
                    var encrypted = rsa.Encrypt(plain, RSAEncryptionPadding.OaepSHA256);
                    model.EncryptedText = Convert.ToBase64String(encrypted);

                    var decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
                    model.DecryptedText = Encoding.UTF8.GetString(decrypted);
                }

                //Bouncy Castle AES
                else if (model.Algorithm == "BouncyCastle") 
                {
                    var key = string.IsNullOrEmpty(model.Key) ? new byte[32] : Convert.FromBase64String(model.Key);
                    var iv = string.IsNullOrEmpty(model.IV) ? new byte[16] : Convert.FromBase64String(model.IV);

                    if (key.Length != 32) key = new byte[32]; // Проверка длины ключа
                    if (iv.Length != 16) iv = new byte[16];   // Проверка длины IV

                    var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
                    cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

                    var inputBytes = Encoding.UTF8.GetBytes(model.InputText);
                    var outputBytes = cipher.DoFinal(inputBytes);
                    model.EncryptedText = Convert.ToBase64String(outputBytes);

                    cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
                    var decryptedBytes = cipher.DoFinal(outputBytes);
                    model.DecryptedText = Encoding.UTF8.GetString(decryptedBytes);

                    model.Key = Convert.ToBase64String(key);
                    model.IV = Convert.ToBase64String(iv);
                }
                // Libsodium SecretBox
                else if (model.Algorithm == "Libsodium") 
                {
                    var key = string.IsNullOrEmpty(model.Key) ? SecretBox.GenerateKey() : Convert.FromBase64String(model.Key);

                    var nonce = SecretBox.GenerateNonce();
                    var plain = Encoding.UTF8.GetBytes(model.InputText);

                    var encrypted = SecretBox.Create(plain, nonce, key);
                    model.EncryptedText = Convert.ToBase64String(nonce.Concat(encrypted).ToArray()); 

                    var cipherText = Convert.FromBase64String(model.EncryptedText);
                    var extractedNonce = cipherText.Take(24).ToArray();
                    var extractedCipher = cipherText.Skip(24).ToArray();

                    var decrypted = SecretBox.Open(extractedCipher, extractedNonce, key);
                    model.DecryptedText = Encoding.UTF8.GetString(decrypted);

                    model.Key = Convert.ToBase64String(key);
                }
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", $"Ошибка: {ex.Message}");
            }

            return View(model);
        }
    }
}
