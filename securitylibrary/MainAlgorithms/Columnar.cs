
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int columns = 0, firstIndex = 0, secondIndex = 0, PTlen = plainText.Length, CTlen = cipherText.Length;

            for (int i = 0; i < PTlen; i++)
            {
                if (cipherText[0] == plainText[i])
                {
                    firstIndex = i;
                    int j;
                    for (j = firstIndex + 1; j < PTlen - i; j++)
                    {
                        secondIndex = Enumerable.Range(firstIndex + 1, PTlen - firstIndex - 1)
                                                .FirstOrDefault(index => cipherText[1] == plainText[index]);

                        if (secondIndex != -1) break;

                    }


                }
                columns = secondIndex - firstIndex;
                if (columns > 2) break;
            }

            int Row = (PTlen % columns != 0) ? PTlen / columns + 1 : PTlen / columns;
            int PTcount = 0;
            List<int> key = new List<int>(columns);
            char[,] matP = new char[Row, columns];

            for (int i = 0; i < Row; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    if (PTcount < PTlen)
                    {
                        matP[i, j] = plainText[PTcount];
                        PTcount++;
                    }
                    else
                    {
                        matP[i, j] = 'X';
                    }
                }
            }

            char[,] matC = new char[Row, columns];
            int CTcount = 0;
            int rowCT = 0;
            int flag = 0;
            for (int i = 0; i < columns; i++)
            {
                flag = 0;
                for (int row_cipher = rowCT; row_cipher < Row; row_cipher++)
                {
                    if (CTcount < CTlen)
                    {
                        matC[row_cipher, i] = cipherText[CTcount];
                        CTcount++;
                    }
                    if (row_cipher == Row - 1)
                    {
                        for (int columnPlain = 0; columnPlain < columns; columnPlain++)
                        {
                            flag = (matC[Row - 1, i] == matP[Row - 1, columnPlain]) ? 1 : flag;
                        }
                        if (flag == 0 && i + 1 < columns)
                        {
                            rowCT = (flag == 0 && i + 1 < columns) ? 1 : rowCT;
                            char oldMat = (flag == 0 && i + 1 < columns) ? matC[row_cipher, i] : ' ';
                            matC[row_cipher, i] = (flag == 0 && i + 1 < columns) ? 'X' : matC[row_cipher, i];
                            matC[0, i + 1] = (flag == 0 && i + 1 < columns) ? oldMat : matC[0, i + 1];
                        }
                        //else if
                        rowCT = (flag == 1) ? 0 : rowCT;

                    }
                }
            }
            if (matC[Row - 1, columns - 1] == '\0')
            {
                matC[Row - 1, columns - 1] = 'X';
            }

            int plain_count = 0;
            //int cipher_colindex = 0;

            for (int columnPlain = 0; columnPlain < columns; columnPlain++)
            {
                for (int col_cipher = 0; col_cipher < columns; col_cipher++)
                {
                    for (int rows = 0; rows < Row; rows++)
                    {
                        if (matP[rows, columnPlain] == matC[rows, col_cipher])
                        {
                            plain_count += (plain_count == Row) ? 0 : 1;
                            if (plain_count == Row)
                            {
                                key.Add(col_cipher + 1);
                            }
                        }
                        else
                        {
                            plain_count = (matP[rows, columnPlain] != matC[rows, col_cipher]) ? 0 : plain_count;
                            rows = (matP[rows, columnPlain] != matC[rows, col_cipher]) ? Row : rows;
                        }
                    }
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int Column = key.Count;
            int Row = cipherText.Length / Column;
            int cipherLen = cipherText.Length;
            char[,] mat = new char[Row, Column];
            int index = 0;
            int count = 1;

            for (int i = 0; i < Column; i++)
            {
                if (count == key[i] && count <= Column)
                {
                    for (int j = 0; j < Row; j++)
                    {
                        mat[j, i] = (index < cipherLen) ? cipherText[index++] : mat[j, i];
                    }
                    count++;
                    i = -1;
                }

            }
            string plain_text = "";
            for (int i = 0; i < Row; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    plain_text += mat[i, j];
                }
            }
            return plain_text.ToLower();

        }

        public string Encrypt(string plainText, List<int> key)
        {
            int Column = key.Count;
            int PTlen = plainText.Length;
            int Row = (PTlen % Column != 0) ? PTlen / Column + 1 : PTlen / Column;
            char[,] mat = new char[Row, Column];
            int index = 0;

            for (int i = 0; i < Row; i++)
            {
                for (int j = 0; j < Column; j++)
                {
                    mat[i, j] = (index < PTlen) ? mat[i, j] = plainText[index++] : 'x';

                }
            }
            string cipher_text = "";
            int c = 1;
            for (int i = 0; i < Column; i++)
            {
                if (c == key[i] && c <= key.Count)
                {
                    for (int j = 0; j < Row; j++)
                    {
                        cipher_text += mat[j, i];
                    }
                    c++;
                    i = -1;
                }
            }
            return cipher_text.ToUpper();
        }
    }
}

