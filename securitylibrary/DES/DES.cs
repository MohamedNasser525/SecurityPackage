using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {

        public override string Decrypt(string cipherText, string key)
        {
            the_keys.Clear();
            L_R.Clear();
            get_CD(key);
            return get_LR2((cipherText));
        }
        public override string Encrypt(string plainText, string key)
        {
            the_keys.Clear();
            L_R.Clear();
            get_CD(key);
            return create_LR(plainText);
        }


        public List<KeyValuePair<string, string>> C_D = new List<KeyValuePair<string, string>>();
        public List<KeyValuePair<string, string>> L_R = new List<KeyValuePair<string, string>>();
        public List<string> the_keys = new List<string>();

        int[] IP = new int[64]
        {
                58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
        };

        int[] IIP = new int[64] { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7,
                47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5,
                45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3,
                43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1,
                41, 9, 49, 17, 57, 25 };

        int[] Expend = new int[48] { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
                                    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22,
                                    23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };


        int[,] sb1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                                         { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                                         { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                                         { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        int[,] sb2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                                         { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                                         { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                                         { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        int[,] sb3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                                         { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                                         { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                                         { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        int[,] sb4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                                         { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                                         { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                                         { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        int[,] sb5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                                         { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                                         { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                                         { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        int[,] sb6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                                         { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                                         { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                                         { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        int[,] sb7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                                         { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                                         { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                                         { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        int[,] sb8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                                         { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                                         { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                                         { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };


        int[] Permutation = new int[32] { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26,
                                    5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
                                    19, 13, 30, 6, 22, 11, 4, 25 };

        int[] PC1 = new int[56] { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                                    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63,
                                    55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
                                    61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };

        int[] PC2 = new int[48] { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12,
                                       4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55,
                                       30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42,
                                       50, 36, 29, 32 };

        // Step 1: Convert hexadecimal string to binary
        public string ConvertToBinary(string hexadecimalString)
        {
            Dictionary<char, string> hexToBinary = new Dictionary<char, string>()
            {
                {'0', "0000"},
                {'1', "0001"},
                {'2', "0010"},
                {'3', "0011"},
                {'4', "0100"},
                {'5', "0101"},
                {'6', "0110"},
                {'7', "0111"},
                {'8', "1000"},
                {'9', "1001"},
                {'A', "1010"},
                {'B', "1011"},
                {'C', "1100"},
                {'D', "1101"},
                {'E', "1110"},
                {'F', "1111"}
            };

            StringBuilder binaryResult = new StringBuilder();
            for (int i = 2; i < hexadecimalString.Length; i++)
            {
                binaryResult.Append(hexToBinary[hexadecimalString[i]]);
            }

            return binaryResult.ToString();
        }

        // Step 2: Perform Initial Permutation (IP)
        public string InitialPermutation(string input)
        {
            string binaryInput = ConvertToBinary(input);
            StringBuilder permutedInput = new StringBuilder();
            for (int i = 0; i < 64; i++)
            {
                permutedInput.Append(binaryInput[IP[i] - 1]);
            }

            return permutedInput.ToString();
        }


        // Step3 : divide the string into left and right with 32 bits
        public string create_LR(string plainText)
        {
            string IP = InitialPermutation(plainText);
            string init_L = IP.Substring(0, 32);
            string init_R = IP.Substring(32, 32);
            L_R.Add(new KeyValuePair<string, string>(init_L, init_R));

            for (int i = 1; i <= 16; i++)
            {
                string L = L_R[i - 1].Value;
                string R = create_R(L_R[i - 1].Key, L_R[i - 1].Value, the_keys[i]);
                L_R.Add(new KeyValuePair<string, string>(L, R));
            }

            //inverse intial permutation
            string RL = L_R[16].Value + L_R[16].Key;
          
            StringBuilder finalResult = new StringBuilder();
            for (int i = 0; i < 64; i++)
            {
                finalResult.Append(RL[IIP[i] - 1]);
            }

            string cipherText = "0x" + Convert.ToInt64(finalResult.ToString(), 2).ToString("X");
            return cipherText;
        }


       

        //Step 4 : expand right to 48 bits

        public string Expanding(string Right)
        {
             StringBuilder newRight = new StringBuilder();
            for (int i = 0; i < 48; i++)
            {
                newRight.Append(Right[Expend[i] - 1]);
            }

            return newRight.ToString();
        }



        //Step 5 : XOR 
        public string XOR(string x, string y)
        {
            StringBuilder res = new StringBuilder();
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] == y[i])
                    res.Append('0');
                else
                    res.Append('1');
            }
            return res.ToString();
        }



        // get positions of S-Box
        public int positions_of_sbox(string position)
        {
            int res = 0;
            int indx = 0;
            for (int i = position.Length - 1; i >= 0; i--)
                res += ((int)Math.Pow(2, indx++) * (position[i] - '0'));
            return res;
        }


        //Step 6 : apply S-Boxes
        public string create_R(string Left, string Right, string key)
        {
            string ExpendRight = Expanding(Right);
            string outputbeforeSBOX = XOR(ExpendRight, key);

            List<string> MyBlocks = new List<string>();

            int count = 0;
            string addedtoblocks = "";
            for (int i = 0; i < outputbeforeSBOX.Length; i++)
            {
                if (count == 6)
                {
                    MyBlocks.Add(addedtoblocks);
                    addedtoblocks = "";
                    count = 0;
                }
                addedtoblocks += outputbeforeSBOX[i];
                count++;
            }
            MyBlocks.Add(addedtoblocks);
            string strg = "";
            for (int i = 0; i < MyBlocks.Count; i++)
            {
                int row = positions_of_sbox((MyBlocks[i][0].ToString() + MyBlocks[i][5].ToString()));
                int col = positions_of_sbox((MyBlocks[i].Substring(1, 4)).ToString());
                int Sbox = 0;
                switch (i)
                {
                    case 0:
                        Sbox = sb1[row, col];
                        break;
                    case 1:
                        Sbox = sb2[row, col];
                        break;
                    case 2:
                        Sbox = sb3[row, col];
                        break;
                    case 3:
                        Sbox = sb4[row, col];
                        break;
                    case 4:
                        Sbox = sb5[row, col];
                        break;
                    case 5:
                        Sbox = sb6[row, col];
                        break;
                    case 6:
                        Sbox = sb7[row, col];
                        break;
                    case 7:
                        Sbox = sb8[row, col];
                        break;
                    default:
                        // Handle the case when i is out of range
                        break;
                }
                strg += ToBinary(Sbox).ToString();
            }

            StringBuilder res = new StringBuilder();
            for (int i = 0; i < 32; i++)
            {
                res.Append(strg[Permutation[i] - 1]);
            }

            string newRight = XOR(Left, res.ToString());
            return newRight;
        }


        //Step 7 : apply pc1
        public string apply_pc1(string key)
        {
            StringBuilder Newkey = new StringBuilder();
            for (int i = 0; i < 56; i++)
            {
                Newkey.Append(key[PC1[i] - 1]);
            }
            return Newkey.ToString();
        }


        // Step 8 : apply pc2
        public string apply_pc2(string key)
        {
             StringBuilder Newkey = new StringBuilder();
            for (int i = 0; i < 48; i++)
            {
                Newkey.Append(key[PC2[i] - 1]);
            }
            return Newkey.ToString();
        }



        //turn integers into binary
        public string ToBinary(int n)
        {
           string[] binaryArray = 
           {
              "0000", "0001", "0010", "0011",
              "0100", "0101", "0110", "0111",
              "1000", "1001", "1010", "1011",
              "1100", "1101", "1110", "1111"
           };
            return binaryArray[n];
        }
        
        
       //after pc1 shiftleft by 1
        public string shiftby1(string str)
        {
            char z = str[0];
            string res = str.Substring(1) + z;
            return res;
        }
        //after pc1 shiftleft by 2
        public string shiftby2(string str)
        {
            char z1 = str[0], z2 = str[1];
            string res = str.Substring(2) + z1 + z2;
            return res;
        }
        //get the CD
        public void get_CD(string key)
        {
            string input = ConvertToBinary(key);
            string Newkey = apply_pc1(input);
            string initC = Newkey.Substring(0, 28);
            string initD = Newkey.Substring(28, 28);
            the_keys.Add(apply_pc2(initC + initD));
            C_D.Add(new KeyValuePair<string, string>(initC, initD));
            for (int i = 1; i <= 16; i++)
            {
                string x1, x2;
                if (i == 1 || i == 2 || i == 9 || i == 16)
                {
                    x1 = shiftby1(C_D[i - 1].Key);
                    x2 = shiftby1(C_D[i - 1].Value);
                }
                else
                {
                    x1 = shiftby2(C_D[i - 1].Key);
                    x2 = shiftby2(C_D[i - 1].Value);
                }
                C_D.Add(new KeyValuePair<string, string>(x1, x2));
                the_keys.Add(apply_pc2(x1 + x2));
            }

        }


        public static string turn_into_hexa(string n)
        {
            Dictionary<string, string> x = new Dictionary<string, string>();
            x.Add("0000", "0");
            x.Add("0001", "1");
            x.Add("0010", "2");
            x.Add("0011", "3");
            x.Add("0100", "4");
            x.Add("0101", "5");
            x.Add("0110", "6");
            x.Add("0111", "7");
            x.Add("1000", "8");
            x.Add("1001", "9");
            x.Add("1010", "A");
            x.Add("1011", "B");
            x.Add("1100", "C");
            x.Add("1101", "D");
            x.Add("1110", "E");
            x.Add("1111", "F");
            return x[n];
        }
        public string get_LR2(string CT)
        {
            string IP = InitialPermutation(CT);
            string init_L = IP.Substring(0, 32);
            string init_R = IP.Substring(32, 32);
            L_R.Add(new KeyValuePair<string, string>(init_L, init_R));
            for (int i = 1; i <= 16; i++)
            {
                string L = L_R[i - 1].Value;
                string R = create_R(L_R[i - 1].Key, L_R[i - 1].Value, the_keys[the_keys.Count - i]);
                L_R.Add(new KeyValuePair<string, string>(L, R));
            }
            string RL = L_R[16].Value + L_R[16].Key;
            StringBuilder res = new StringBuilder();
            for (int i = 0; i < 64; i++)
            {
                res.Append(RL[IIP[i] - 1]);
            }

            StringBuilder plaintext = new StringBuilder("0x");
            for (int i = 0; i < 64; i += 4)
            {
                string fres = turn_into_hexa(res.ToString().Substring(i, 4));
                plaintext.Append(fres);
            }

            return plaintext.ToString();
        }
       
     
    }
}