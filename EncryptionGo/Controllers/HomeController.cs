using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using EncryptionGo.Models;
using Microsoft.AspNetCore.Mvc;

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
                if (model.Algorithm == "AES") //  AES
                {
                    using var aes = Aes.Create();

                    // �������� ����� � IV, ���� ������������� �������������
                    if (!string.IsNullOrEmpty(model.Key))
                        aes.Key = Convert.FromBase64String(model.Key);
                    else
                        model.Key = Convert.ToBase64String(aes.Key);

                    if (!string.IsNullOrEmpty(model.IV))
                        aes.IV = Convert.FromBase64String(model.IV);
                    else
                        model.IV = Convert.ToBase64String(aes.IV);

                    // ���������� 
                    var plain = Encoding.UTF8.GetBytes(model.InputText);
                    using var encryptor = aes.CreateEncryptor();
                    var encrypted = encryptor.TransformFinalBlock(plain, 0, plain.Length);
                    model.EncryptedText = Convert.ToBase64String(encrypted);

                    // ������������ 
                    using var decryptor = aes.CreateDecryptor();
                    var decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
                    model.DecryptedText = Encoding.UTF8.GetString(decrypted);
                }
                else if (model.Algorithm == "RSA") //RSA
                {
                    using var rsa = RSA.Create(2048);

                    // ��������� � ��������� �����
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

                    // ���������� 
                    var plain = Encoding.UTF8.GetBytes(model.InputText);
                    var encrypted = rsa.Encrypt(plain, RSAEncryptionPadding.OaepSHA256);
                    model.EncryptedText = Convert.ToBase64String(encrypted);

                    // ������������ 
                    var decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
                    model.DecryptedText = Encoding.UTF8.GetString(decrypted);
                }
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", $"������: {ex.Message}");
            }

            return View(model);
        }
    }
}
