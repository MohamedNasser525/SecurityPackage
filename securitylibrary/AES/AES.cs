using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    /// 
    public class AES : CryptographicTechnique
    {
        string[] RconTable = new string[11];

        int NofR = 10;
        string[,] kSHandling = new string[4, 44];
        string[,] input = new string[4, 4];
        string[,] substituteBox = new string[16, 16] {
                { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
                { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
                { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
                { "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
                { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
                { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
                { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
                { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
                { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
                { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
                { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
                { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
                { "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A" },
                { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
                { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
                { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" }
            };

        readonly string[,] MXstep = new string[4, 4] { { "02", "03", "01", "01" }, { "01", "02", "03", "01" }, { "01", "01", "02", "03" }, { "03", "01", "01", "02" } };
        readonly string[,] invMXCstep = new string[4, 4] { { "0e", "0b", "0d", "09" }, { "09", "0e", "0b", "0d" }, { "0d", "09", "0e", "0b" }, { "0b", "0d", "09", "0e" } };
        string[,] invSubstituteBox = new string[16, 16] {
                { "52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB" },
                { "7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB" },
                { "54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E" },
                { "08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25" },
                { "72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92" },
                { "6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84" },
                { "90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06" },
                { "D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B" },
                { "3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73" },
                { "96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E" },
                { "47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B" },
                { "FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4" },
                { "1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F" },
                { "60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF" },
                { "A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61" },
                { "17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D" }
    };
        string[,] ETable = new string[16, 16]
                {
            { "01", "03", "05", "0F", "11", "33", "55", "FF", "1A", "2E", "72", "96", "A1", "F8", "13", "35"},
            { "5F", "E1", "38", "48", "D8", "73", "95", "A4", "F7", "02", "06", "0A", "1E", "22", "66", "AA"},
            { "E5", "34", "5C", "E4", "37", "59", "EB", "26", "6A", "BE", "D9", "70", "90", "AB", "E6", "31"},
            { "53", "F5", "04", "0C", "14", "3C", "44", "CC", "4F", "D1", "68", "B8", "D3", "6E", "B2", "CD"},
            { "4C", "D4", "67", "A9", "E0", "3B", "4D", "D7", "62", "A6", "F1", "08", "18", "28", "78", "88"},
            { "83", "9E", "B9", "D0", "6B", "BD", "DC", "7F", "81", "98", "B3", "CE", "49", "DB", "76", "9A"},
            { "B5", "C4", "57", "F9", "10", "30", "50", "F0", "0B", "1D", "27", "69", "BB", "D6", "61", "A3"},
            { "FE", "19", "2B", "7D", "87", "92", "AD", "EC", "2F", "71", "93", "AE", "E9", "20", "60", "A0"},
            { "FB", "16", "3A", "4E", "D2", "6D", "B7", "C2", "5D", "E7", "32", "56", "FA", "15", "3F", "41"},
            { "C3", "5E", "E2", "3D", "47", "C9", "40", "C0", "5B", "ED", "2C", "74", "9C", "BF", "DA", "75"},
            { "9F", "BA", "D5", "64", "AC", "EF", "2A", "7E", "82", "9D", "BC", "DF", "7A", "8E", "89", "80"},
            { "9B", "B6", "C1", "58", "E8", "23", "65", "AF", "EA", "25", "6F", "B1", "C8", "43", "C5", "54"},
            { "FC", "1F", "21", "63", "A5", "F4", "07", "09", "1B", "2D", "77", "99", "B0", "CB", "46", "CA" },
            { "45", "CF", "4A", "DE", "79", "8B", "86", "91", "A8", "E3", "3E", "42", "C6", "51", "F3", "0E"},
            { "12", "36", "5A", "EE", "29", "7B", "8D", "8C", "8F", "8A", "85", "94", "A7", "F2", "0D", "17"},
            { "39", "4B", "DD", "7C", "84", "97", "A2", "FD", "1C", "24", "6C", "B4", "C7", "52", "F6", "01"}
            };

        string[,] LTable = new string[16, 16] {
            { "","00", "19", "01", "32", "02", "1A", "C6", "4B", "C7", "1B", "68", "33", "EE", "DF", "03"},
            { "64", "04", "E0", "0E", "34", "8D", "81", "EF", "4C", "71", "08", "C8", "F8", "69", "1C", "C1"},
            { "7D", "C2", "1D", "B5", "F9", "B9", "27", "6A", "4D", "E4", "A6", "72", "9A", "C9", "09", "78"},
            { "65", "2F", "8A", "05", "21", "0F", "E1", "24", "12", "F0", "82", "45", "35", "93", "DA", "8E"},
            { "96", "8F", "DB", "BD", "36", "D0", "CE", "94", "13", "5C", "D2", "F1", "40", "46", "83", "38"},
            { "66", "DD", "FD", "30", "BF", "06", "8B", "62", "B3", "25", "E2", "98", "22", "88", "91", "10"},
            { "7E", "6E", "48", "C3", "A3", "B6", "1E", "42", "3A", "6B", "28", "54", "FA", "85", "3D", "BA"},
            { "2B", "79", "0A", "15", "9B", "9F", "5E", "CA", "4E", "D4", "AC", "E5", "F3", "73", "A7", "57"},
            { "AF", "58", "A8", "50", "F4", "EA", "D6", "74", "4F", "AE", "E9", "D5", "E7", "E6", "AD", "E8"},
            { "2C", "D7", "75", "7A", "EB", "16", "0B", "F5", "59", "CB", "5F", "B0", "9C", "A9", "51", "A0" },
            { "7F", "0C", "F6", "6F", "17", "C4", "49", "EC", "D8", "43", "1F", "2D", "A4", "76", "7B", "B7"},
            { "CC", "BB", "3E", "5A", "FB", "60", "B1", "86", "3B", "52", "A1", "6C", "AA", "55", "29", "9D"},
            { "97", "B2", "87", "90", "61", "BE", "DC", "FC", "BC", "95", "CF", "CD", "37", "3F", "5B", "D1"},
            { "53", "39", "84", "3C", "41", "A2", "6D", "47", "14", "2A", "9E", "5D", "56", "F2", "D3", "AB"},
            { "44", "11", "92", "D9", "23", "20", "2E", "89", "B4", "7C", "B8", "26", "77", "99", "E3", "A5"},
            { "67", "4A", "ED", "DE", "C5", "31", "FE", "18", "0D", "63", "8C", "80", "C0", "F7", "70", "07"}
            };
        //buildLTable
        string MFIMC(string hexA, string hexB)
        {
            // Ensure both hex strings are at least 2 characters long
            hexA = hexA.PadLeft(2, '0');
            hexB = hexB.PadLeft(2, '0');

            // Return "00" if either input is "00" after padding
            switch (hexA)
            {
                case "00":
                    return "00";
                default:
                    switch (hexB)
                    {
                        case "00":
                            return "00";
                        default:
                            // Add code here for other conditions or the default case if hexA and hexB are not "00"
                            break;
                    }
                    break;
            }


            int firstRow = Convert.ToInt32(hexA.Substring(0, 1), 16);
            int column1 = Convert.ToInt32(hexA.Substring(1, 1), 16);
            int secondRow = Convert.ToInt32(hexB.Substring(0, 1), 16);
            int column2 = Convert.ToInt32(hexB.Substring(1, 1), 16);

            int result = Convert.ToInt32(LTable[firstRow, column1], 16) + Convert.ToInt32(LTable[secondRow, column2], 16);
            int maximumValue = Convert.ToInt32("FF", 16); // You can convert this once and reuse it
            bool condition = result > maximumValue;

            switch (condition)
            {
                case true:
                    result -= maximumValue; // Equivalent to sum = sum - maxVal;
                    break;
                default:
                    // Do nothing or handle other logic here
                    break;
            }
            string answer = result.ToString("X2");
            int defaultRow = Convert.ToInt32(answer.Substring(0, 1), 16);
            int defaultColumn = Convert.ToInt32(answer.Substring(1, 1), 16);
            return ETable[defaultRow, defaultColumn];
        } //multiplyForInverseMixColumns
          //invmixColumnsOperation


        public override string Decrypt(string cipherText, string key)
        {
            NofR = 10;
            RconTable[0] = "01";
            RconTable[1] = "02";
            RconTable[2] = "04";
            RconTable[3] = "08";
            RconTable[4] = "10";
            RconTable[5] = "20";
            RconTable[6] = "40";
            RconTable[7] = "80";
            RconTable[8] = "1b";
            RconTable[9] = "36";
            RconTable[10] = "6c";

            key = key.Substring(2);
            int jj = 0;
            while (jj < 4)
            {
                int i = 0;
                while (i < 4)
                {
                    kSHandling[i, jj] = key.Substring(0, 2);
                    key = key.Substring(2);
                    i++;
                }
                jj++;
            }

            int round = 1;
            int col1 = 4;
            while (col1 < 44)
            {
                switch (col1 % 4)
                {
                    case 0:
                        string[,] variable1 = new string[4, 1];
                        int i = 0;
                        while (i < 4)
                        {
                            variable1[i, 0] = kSHandling[i, col1 - 1];
                            i++;
                        }
                        // shift temp
                        string variableValue = variable1[0, 0];
                        i = 0;
                        while (i < 3)
                        {
                            variable1[i, 0] = variable1[i + 1, 0];
                            i++;
                        }
                        variable1[3, 0] = variableValue;
                        // subsistute with SBox
                        SBS(ref variable1, 4, 1);
                        // XOR with Rcon
                        variable1[0, 0] = Convert.ToString(Convert.ToInt32(variable1[0, 0], 16) ^ Convert.ToInt32(RconTable[round - 1], 16), 16);
                        round++;
                        // add to keySchedule
                        i = 0;
                        while (i < 4)
                        {
                            kSHandling[i, col1] = Convert.ToString(Convert.ToInt32(kSHandling[i, col1 - 4], 16) ^ Convert.ToInt32(variable1[i, 0], 16), 16);
                            i++;
                        }
                        break;

                    default:
                        i = 0;
                        while (i < 4)
                        {
                            kSHandling[i, col1] = Convert.ToString(Convert.ToInt32(kSHandling[i, col1 - 1], 16) ^ Convert.ToInt32(kSHandling[i, col1 - 4], 16), 16);
                            i++;
                        }
                        break;
                }
                col1++;
            }



            cipherText = cipherText.Substring(2);
            int jjj = 0;
            while (jjj < 4)
            {
                int i = 0;
                while (i < 4)
                {
                    input[i, jjj] = cipherText.Substring(0, 2);
                    cipherText = cipherText.Substring(2);
                    i++;
                }
                jjj++;
            }


            ARK(NofR);
            NofR--;
            string[,] variable2 = new string[4, 4];
            int ii = 0;
            while (ii < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    variable2[ii, j] = input[ii, j];
                    j++;
                }
                ii++;
            }

            int iii = 0;
            while (iii < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    // Compute the index with wrapping at 4 and handling negative indices
                    int index = (((j - iii) % 4) + 4) % 4;
                    input[iii, j] = variable2[iii, index];
                    j++;
                }
                iii++;
            }


            int iiii = 0;
            while (iiii < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    string ayhaga = input[iiii, j];
                    switch (ayhaga.Length)
                    {
                        case 1: // Equivalent to if (cell.Length == 1)
                            ayhaga = "0" + ayhaga;
                            break;
                        default:
                            break; // Do nothing if not length 1
                    }

                    int defaultRow = Convert.ToInt32(ayhaga.Substring(0, 1), 16);
                    int defaultColumn = Convert.ToInt32(ayhaga.Substring(1, 1), 16);
                    input[iiii, j] = invSubstituteBox[defaultRow, defaultColumn];

                    j++;
                }
                iiii++;
            }
            int K1 = NofR;
            while (K1 > 0)
            {
                ARK(K1);

                int col3 = 0;
                while (col3 < 4)
                {
                    string[,] stateMatrix = new string[4, 1];
                    int i1 = 0;
                    while (i1 < 4)
                    {
                        stateMatrix[i1, 0] = input[i1, col3];
                        i1++;
                    }

                    string[,] tcms = new string[4, 1];
                    int i2 = 0;
                    while (i2 < 4)
                    {
                        int z = 0;
                        while (z < 4)
                        {
                            tcms[z, 0] = invMXCstep[i2, z];
                            z++;
                        }
                        string variable3 = "";
                        int j1 = 0;
                        while (j1 < 4)
                        {
                            string answer = MFIMC(tcms[j1, 0], stateMatrix[j1, 0]);
                            answer = Convert.ToString(Convert.ToInt32(answer, 16), 2).PadLeft(8, '0');
                            variable3 = operationXOR(variable3, answer);
                            j1++;
                        }
                        input[i2, col3] = Convert.ToString(Convert.ToInt32(variable3, 2), 16);
                        i2++;
                    }
                    col3++;
                }

                string[,] varaible4 = new string[4, 4];
                int i3 = 0;
                while (i3 < 4)
                {
                    int j3 = 0;
                    while (j3 < 4)
                    {
                        varaible4[i3, j3] = input[i3, j3];
                        j3++;
                    }
                    i3++;
                }

                int i4 = 0;
                while (i4 < 4)
                {
                    int j4 = 0;
                    while (j4 < 4)
                    {
                        input[i4, j4] = varaible4[i4, (((j4 - i4) % 4) + 4) % 4];
                        j4++;
                    }
                    i4++;
                }

                int i5 = 0;
                while (i5 < 4)
                {
                    int j5 = 0;
                    while (j5 < 4)
                    {
                        string cell = input[i5, j5];
                        switch (cell.Length)
                        {
                            case 1:
                                cell = "0" + cell;
                                break;
                        }
                        int outputRow = Convert.ToInt32(cell.Substring(0, 1), 16);
                        int outputColumn = Convert.ToInt32(cell.Substring(1, 1), 16);
                        input[i5, j5] = invSubstituteBox[outputRow, outputColumn];
                        j5++;
                    }
                    i5++;
                }
                K1--;
            }

            ARK(0);
            string output = "";
            int i6 = 0;
            while (i6 < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    switch (input[j, i6].Length)
                    {
                        case 1: // Only case where original condition 'input[j, i].Length < 2' is true
                            input[j, i6] = "0" + input[j, i6];
                            break;
                        default:
                            // Do nothing if condition does not meet
                            break;
                    }
                    output += input[j, i6];
                    j++;
                }
                i6++;
            }

            return "0x" + output;
        }

        string operationXOR(string fitst, string second)
        {
            // Handle empty input string A using switch statement
            switch (fitst)
            {
                case "":
                    return second;
            }

            char[] result = new char[fitst.Length];
            int i = 0;

            // Replace for loop with a while loop
            while (i < fitst.Length)
            {
                // Check if the current characters in A and B are the same or different
                switch (fitst.Substring(i, 1) == second.Substring(i, 1))
                {
                    case true:
                        result[i] = '0';
                        break;
                    case false:
                        result[i] = '1';
                        break;
                }
                i++;
            }

            return string.Concat(fitst.Zip(second, (x, y) => x == y ? '0' : '1'));
        }

        string MBY02(string result, bool isBinary = true)
        {
            // Initialize binary representation of input
            string digit;

            // Convert based on the value of isBinary using switch statement
            switch (isBinary)
            {
                case false:
                    // Convert from hex to binary with padding to ensure 8 bits
                    digit = Convert.ToString(Convert.ToInt32(result, 16), 2).PadLeft(8, '0');
                    break;
                default:
                    digit = result;
                    break;
            }

            // Perform left shift manually by slicing and appending '0'
            string shdigit = digit.Substring(1) + "0";

            // Determine the action based on the most significant bit (MSB) of the original binary
            switch (digit[0])
            {
                case '1':
                    shdigit = operationXOR(shdigit, "00011011");
                    break;
            }

            return shdigit;
        }
        //multiplyBy02
        string MBY03(string income)
        {
            // Validate input to ensure it's a valid hex and not null/empty
            if (string.IsNullOrWhiteSpace(income) || income.Length > 2)
                throw new ArgumentException("Input should be a 2-character hexadecimal string.");

            int number;
            if (!int.TryParse(income, System.Globalization.NumberStyles.HexNumber, null, out number))
                throw new ArgumentException("Input is not a valid hexadecimal number.");

            // Convert hexadecimal input to a binary string with padding to ensure 8 bits
            string digit = Convert.ToString(number, 2).PadLeft(8, '0');

            // Perform operations as previously done in MBY02
            string shdigit = digit.Substring(1) + "0";
            if (digit[0] == '1')
                shdigit = operationXOR(shdigit, "00011011");

            // XOR the result of MBY02 operation with the original binary representation
            string result = operationXOR(shdigit, digit);

            return result;
        }//multiplyBy03

        /// <summary>
        /// Performs substitution on all elements of a given matrix based on a predefined substitution box.
        /// </summary>
        /// <param name="inputMatrix">Matrix of hex string values to be processed.</param>
        /// <param name="numberofrows">Number of rows in the matrix.</param>
        /// <param name="numberofcols">Number of columns in the matrix.</param>
        void SBS(ref string[,] inputMatrix, int numberofrows, int numberofcols)
        {
            switch (inputMatrix)
            {
                case null:
                    throw new ArgumentNullException(nameof(inputMatrix), "Input matrix cannot be null.");
                default:
                    // Code for non-null case, if any.
                    break;
            }

            // Assume substituteBox is a globally accessible two-dimensional array.
            int i = 0;
            while (i < numberofrows)
            {
                int j = 0;
                while (j < numberofcols)
                {
                    string cell = inputMatrix[i, j];
                    switch (cell.Length)
                    {
                        case 1:
                            inputMatrix[i, j] = "0" + cell;
                            break;
                    }

                    // Converting and checking within bounds for substituteBox
                    int row = Convert.ToInt32(inputMatrix[i, j].Substring(0, 1), 16);
                    int col = Convert.ToInt32(inputMatrix[i, j].Substring(1, 1), 16);

                    // Handle boundary checks using a switch statement, though it's a bit forced
                    bool isOutOfBounds = row >= substituteBox.GetLength(0) || col >= substituteBox.GetLength(1);
                    switch (isOutOfBounds)
                    {
                        case true:
                            throw new IndexOutOfRangeException("Substitution box indices are out of range.");
                    }

                    inputMatrix[i, j] = substituteBox[row, col];
                    j++;
                }
                i++;
            }

        }
        //sBoxSubistitution

        void ARK(int round)
        {
            int i = 0; // Initialize the outer loop counter
            while (i < 4)
            {
                int j = 0; // Initialize the inner loop counter
                while (j < 4)
                {
                    // Perform XOR between input and key schedule handling, both converted from hex to integer and back to hex
                    input[i, j] = Convert.ToString(
                        Convert.ToInt32(input[i, j], 16) ^ Convert.ToInt32(kSHandling[i, j + round * 4], 16),
                        16
                    );

                    j++; // Increment inner loop counter
                }
                i++; // Increment outer loop counter
            }
        }
        //addRoundKey
        public override string Encrypt(string plainText, string key)
        {
            NofR = 10;
            RconTable[0] = "01";
            RconTable[1] = "02";
            RconTable[2] = "04";
            RconTable[3] = "08";
            RconTable[4] = "10";
            RconTable[5] = "20";
            RconTable[6] = "40";
            RconTable[7] = "80";
            RconTable[8] = "1b";
            RconTable[9] = "36";
            RconTable[10] = "6c";
            key = key.Substring(2);
            int j1 = 0;
            while (j1 < 4)
            {
                int i = 0;
                while (i < 4)
                {
                    kSHandling[i, j1] = key.Substring(0, 2);
                    key = key.Substring(2);
                    i++;
                }
                j1++;
            }

            int round2 = 1;
            int col1 = 4;
            while (col1 < 44)
            {
                switch (col1 % 4)
                {
                    case 0:  // Case when col1 % 4 is 0, equivalent to if (col1 % 4 == 0)
                        {
                            string[,] variable1 = new string[4, 1];
                            int i = 0;
                            while (i < 4)
                            {
                                variable1[i, 0] = kSHandling[i, col1 - 1];
                                i++;
                            }
                            string variableValue = variable1[0, 0];
                            i = 0;
                            while (i < 3)
                            {
                                variable1[i, 0] = variable1[i + 1, 0];
                                i++;
                            }
                            variable1[3, 0] = variableValue;
                            SBS(ref variable1, 4, 1);
                            variable1[0, 0] = Convert.ToString(Convert.ToInt32(variable1[0, 0], 16) ^ Convert.ToInt32(RconTable[round2 - 1], 16), 16);
                            round2++;
                            i = 0;
                            while (i < 4)
                            {
                                kSHandling[i, col1] = Convert.ToString(Convert.ToInt32(kSHandling[i, col1 - 4], 16) ^ Convert.ToInt32(variable1[i, 0], 16), 16);
                                i++;
                            }
                            break;
                        }
                    default:  // Default case, equivalent to else part
                        {
                            int i = 0;
                            while (i < 4)
                            {
                                kSHandling[i, col1] = Convert.ToString(Convert.ToInt32(kSHandling[i, col1 - 1], 16) ^ Convert.ToInt32(kSHandling[i, col1 - 4], 16), 16);
                                i++;
                            }
                            break;
                        }
                }
                col1++;
            }

            plainText = plainText.Substring(2);
            int j2 = 0;
            while (j2 < 4)
            {
                int i = 0;
                while (i < 4)
                {
                    input[i, j2] = plainText.Substring(0, 2);
                    plainText = plainText.Substring(2);
                    i++;
                }
                j2++;
            }

            ARK(0);
            int round = 1;
            while (round <= 9)
            {
                SBS(ref input, 4, 4);
                string[,] temp5 = new string[4, 4];
                int i = 0;
                while (i < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        temp5[i, j] = input[i, j];
                        j++;
                    }
                    i++;
                }

                i = 0;
                while (i < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        input[i, j] = temp5[i, (j + i) % 4];
                        j++;
                    }
                    i++;
                }

                int col = 0;
                while (col < 4)
                {
                    string[,] stateMatrix = new string[4, 1];
                    i = 0;
                    while (i < 4)
                    {
                        stateMatrix[i, 0] = input[i, col];
                        i++;
                    }

                    string[,] tcsm = new string[4, 1];
                    i = 0;
                    while (i < 4)
                    {
                        int z = 0;
                        while (z < 4)
                        {
                            tcsm[z, 0] = MXstep[i, z];
                            z++;
                        }
                        string temp = "";
                        int j = 0;
                        while (j < 4)
                        {
                            switch (tcsm[j, 0])
                            {
                                case "02":
                                    temp = operationXOR(temp, MBY02(stateMatrix[j, 0], false));
                                    break;
                                case "03":
                                    temp = operationXOR(temp, MBY03(stateMatrix[j, 0]));
                                    break;
                                default:
                                    temp = operationXOR(temp, Convert.ToString(Convert.ToInt32(stateMatrix[j, 0], 16), 2).PadLeft(8, '0'));
                                    break;
                            }
                            j++;
                        }
                        input[i, col] = Convert.ToString(Convert.ToInt32(temp, 2), 16);
                        i++;
                    }
                    col++;
                }
                ARK(round);
                round++;
            }

            SBS(ref input, 4, 4);
            string[,] temp6 = new string[4, 4];
            int i3 = 0;
            while (i3 < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    temp6[i3, j] = input[i3, j];
                    j++;
                }
                i3++;
            }

            int i4 = 0;
            while (i4 < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    input[i4, j] = temp6[i4, (j + i4) % 4];
                    j++;
                }
                i4++;
            }

            ARK(10);
            string cipherText = "";
            int i5 = 0;
            while (i5 < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    switch (input[j, i5].Length < 2)
                    {
                        case true: // Replaces 'if' condition
                            input[j, i5] = "0" + input[j, i5];
                            break;
                        default:
                            break; // 'default' case here just to match the 'switch' structure; it does nothing.
                    }
                    cipherText += input[j, i5].ToUpper();
                    j++;
                }
                i5++;
            }

            return "0x" + cipherText;
        }
    }
}
