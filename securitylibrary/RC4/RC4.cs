using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary.RC4
{
    public class RC4Algorithm
    {

        public static string StringToHex(string input)
        {
            string output = "";
            int i = 0;
            while (i < input.Length)
            {
                output += ((int)input[i]).ToString("x2");
                i++;
            }
            return output.ToLower();
        }
        public static string HexToString(string hk)
        {
            string results = "";
            int i = 0;
            while (i < hk.Length)
            {
                string hkpir = hk.Substring(i, 2);
                int chval = Convert.ToInt32(hkpir, 16);
                char chfromhk = Convert.ToChar(chval);
                results += chfromhk;
                i += 2;
            }
            return results;
        }
        public string Decrypt(string cipher, string keyy)
        {
            bool hk1 = false;
            string rt = "";
            int i = 0;
            while (i < 2)
            {
                if (keyy[i] != '0' || keyy[i + 1] != 'x')
                    break;

                keyy = keyy.Substring(2, 8);
                cipher = cipher.Substring(2, 8);
                hk1 = true;
                keyy = HexToString(keyy);
                cipher = HexToString(cipher);
                i++;
            }

            List<int> q = new List<int>();
            List<char> T = new List<char>();
            i = 0;
            while (i < 256)
            {
                q.Add(i);
                i++;
            }
            string tReeep = "";
            while (tReeep.Length < 256)
            {
                tReeep = tReeep.Insert(tReeep.Length, keyy);
            }

            i = 0;
            while (i < tReeep.Length)
            {
                T.Add(tReeep[i]);
                i++;
            }
            int j = 0;
            i = 0;
            while (i < 256)
            {
                j = (j + q[i] + T[i]) % 256;
                int temp = q[i];
                q[i] = q[j];
                q[j] = temp;
                i++;
            }
            int n = 0, k = 0;
            i = 0;
            while (i < cipher.Length)
            {
                n = (n + 1) % 256;
                k = (k + q[n]) % 256;
                int temp = q[n];
                q[n] = q[k];
                q[k] = temp;
                int t = (q[n] + q[k]) % 256;
                int v = q[t];
                int result = cipher[i] ^ v;
                rt = rt.Insert(rt.Length, ((char)result).ToString());
                i++;
            }
            if (hk1)
            {
                rt = StringToHex(rt);
                rt = "0x" + rt;
            }

            return rt;
        }
        public string Encrypt(string plText, string key)
        {
            bool hk2 = false;

            string ciphertxt = "";
            if (key[0] == '0' && key[1] == 'x')
            {
                key = key.Substring(2, 8);
                plText = plText.Substring(2, 8);
                hk2 = true;
                key = HexToString(key);
                plText = HexToString(plText);
            }

            List<int> sp = new List<int>();
            List<char> T = new List<char>();
            int i = 0;
            while (i < 256)
            {
                sp.Add(i);
                i++;
            }
            string tttRep = "";
            while (tttRep.Length < 256)
            {
                tttRep = tttRep.Insert(tttRep.Length, key);
            }

            i = 0;
            while (i < tttRep.Length)
            {
                T.Add(tttRep[i]);
                i++;
            }
            int j = 0;
            i = 0;
            while (i < 256)
            {
                j = (j + sp[i] + T[i]) % 256;
                int temp = sp[i];
                sp[i] = sp[j];
                sp[j] = temp;
                i++;
            }
            int n = 0, k = 0;
            i = 0;
            while (i < plText.Length)
            {
                n = (n + 1) % 256;
                k = (k + sp[n]) % 256;
                int temp = sp[n];
                sp[n] = sp[k];
                sp[k] = temp;
                int t = (sp[n] + sp[k]) % 256;
                int v = sp[t];
                int result = plText[i] ^ v;
                ciphertxt = ciphertxt.Insert(ciphertxt.Length, ((char)result).ToString());
                i++;
            }
            if (hk2)
            {
                ciphertxt = StringToHex(ciphertxt);
                ciphertxt = "0x" + ciphertxt;
            }

            return ciphertxt;
        }
    }
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipher, string keyy)
        {
            RC4Algorithm algorithm = new RC4Algorithm();
            return algorithm.Decrypt(cipher, keyy);
        }

        public override string Encrypt(string plText, string key)
        {
            RC4Algorithm algorithm = new RC4Algorithm();
            return algorithm.Encrypt(plText, key);
        }

        // Modified HexToString method integrating from RC4Algorithm
        public static string HexToString(string hk)
        {
            return RC4Algorithm.HexToString(hk);
        }
    }
}