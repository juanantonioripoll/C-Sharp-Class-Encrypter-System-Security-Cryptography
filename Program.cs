using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encrypter
{
    class Encrypter
    {
        //Encrypt
        public static string Encrypt(string textoencrypt, String pass)
        {
            try
            {
                string EncryptionKey = pass;
                byte[] clearBytes = Encoding.Unicode.GetBytes(textoencrypt);
                using (Aes encryptor = Aes.Create())
                {
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey,
                        new byte[] { 0x49, 0x76, 0x61, 0x6E, 0x20,
                            0x4D, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });

                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms,
                            encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(clearBytes, 0, clearBytes.Length);
                            cs.Close();
                        }
                        textoencrypt = Convert.ToBase64String(ms.ToArray());
                    }
                }
                return textoencrypt;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        //Decrypt
        public static string Decrypt(string textodecrypt, string pass)
        {
            try
            {
                string EncryptionKey = pass;
                if (textodecrypt != null)
                    textodecrypt = textodecrypt.Replace(" ", "+");
                byte[] cipherBytes = Convert.FromBase64String(textodecrypt);
                using (Aes encryptor = Aes.Create())
                {
                    Rfc2898DeriveBytes pdb =
                        new Rfc2898DeriveBytes(EncryptionKey,
                        new byte[] { 0x49, 0x76, 0x61, 0x6E, 0x20,
                            0x4D, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms,
                            encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(cipherBytes, 0, cipherBytes.Length);
                            cs.Close();
                        }
                        textodecrypt =
                            Encoding.Unicode.GetString(ms.ToArray());
                    }
                }
                return textodecrypt;
            }
            catch (Exception)
            {
                return "... Incorrect Phrase!";
            }
        }
    }

    internal class Program
    {
        static void Main(string[] args)
        {
            bool debug = true;
            string text;
            string pass;

            Console.WriteLine("Enter text for Encrypt:");
            text = Console.ReadLine();
            Console.WriteLine("Enter Phrase:");
            pass = Console.ReadLine();

            //Encrypt
            text = Encrypter.Encrypt(text, pass);
            Console.WriteLine("Text Encrypted: {0}", text);
            Console.WriteLine("");

            //Decrypt
            Console.WriteLine("Enter Phrase to Decrypt:");
            pass = Console.ReadLine();
            string TextDecrypted =
            Encrypter.Decrypt(text, pass);
            Console.WriteLine("Text Decrypted: {0}",
            TextDecrypted);

            if (debug)
                Console.ReadLine();

        }
    }
}
