using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace TestClient
{
    public class CBORDiagnostics
    {
        public static CBORObject Parse(string input)
        {
            CBORDiagnostics diag = new CBORDiagnostics(input);

            return diag.ParseToCBOR();
        }

        private string _input;
        private int _offset;

        private char Next
        {
            get => _input[_offset];
        }

        private bool EndOfString
        {
            get => _input.Length == _offset;
        }

        public CBORDiagnostics(string input)
        {
            _input = input;
            _offset = 0;
        }

        CBORObject ParseToCBOR()
        {
            SkipWhiteSpace();

            if (EndOfString) return null;
            if (Next == '{') return ParseMap();
            if (Next == '[') return ParseArray();
            if (char.IsDigit(Next) || Next == '-') {
                CBORObject num = ParseNumber();

                if (Next == '(') {
                    return ParseTag(num);
                }

                return num;
            }
            if (Next == 'h') return ParseBinary();
            if (Next == '\'') return ParseBinary();
            if (Next == '"') return ParseString();

            return null;
        }


        private CBORObject ParseArray()
        {
            CBORObject array = CBORObject.NewArray();

            if (Next != '[') throw new Exception("ICE");

            do {
                _offset += 1;
                array.Add(ParseToCBOR());
                SkipWhiteSpace();
            } while (Next == ',');

            if (Next != ']') throw new Exception("Invalid input: offset = " + _offset);
            _offset += 1;

            return array;
        }

        private CBORObject ParseBinary()
        {
            if (Next == 'h') {
                _offset += 1;
                if (Next != '\'') throw new Exception("Invalid input offset = " + _offset);
                _offset += 1;
                int start = _offset;
                while (Next != '\'') _offset += 1;
                string value = _input.Substring(start, _offset - start);
                value = value.Replace(" ", "");

                _offset += 1;

                return CBORObject.FromObject(StringToByteArray(value));
            }
            else if (Next == '\'') {
                _offset += 1;
                int start = _offset;
                while (Next != '\'') _offset += 1;
                _offset += 1;
                string valueIn = _input.Substring(start, _offset - start - 1);
                byte[] value = new byte[valueIn.Length];
                for (int i = 0; i < valueIn.Length; i++) value[i] = (byte) valueIn[i];
                return CBORObject.FromObject(value);
            }
            else {
                throw new Exception("Invalid format: offset = "+ _offset);
            }
        }

        private CBORObject ParseMap()
        {
            CBORObject map = CBORObject.NewMap();
            CBORObject key;

            if (Next != '{') throw new Exception("ICE " + _offset);
            if (_input[_offset + 1] == '}') {
                _offset += 2;
                return map;
            }

            do {
                _offset += 1;
                key = ParseToCBOR();
                SkipWhiteSpace();
                if (Next != ':') throw new Exception("Invalid input offset=" + _offset);
                _offset += 1;
                SkipWhiteSpace();
                map.Add(key, ParseToCBOR());
                SkipWhiteSpace();
            } while (Next == ',');

            if (Next != '}') throw new Exception("Invalid input: offset=" + _offset);
            _offset += 1;

            return map;
        }

        private CBORObject ParseNumber()
        {
            if (!char.IsDigit(Next) && Next != '-') throw new Exception("ICE " + _offset);

            int value = 0;
            bool neg = false;
            if (Next == '-') {
                neg = true;
                _offset += 1;
            }

            while (char.IsDigit(Next)) {
                value = value * 10 + Next - '0';
                _offset += 1;
            }

            if (neg) value = -value;

            return CBORObject.FromObject(value);
        }

        private CBORObject ParseString()
        {
            if (Next == '"') {
                _offset += 1;
                int start = _offset;
                while (Next != '"') _offset += 1;
                _offset += 1;

                return CBORObject.FromObject(_input.Substring(start, _offset - 1 - start));
            }
            else {
                throw new Exception("Invalid input offset = " + _offset);
            }
        }

        private CBORObject ParseTag(CBORObject tagNum)
        {
            if (Next != '(') {
                throw new Exception("Invalid tag format");
            }

            _offset += 1;

            CBORObject content = ParseToCBOR();

            if (Next != ')') {
                throw new Exception("Invalid tag format");
            }

            _offset += 1;

            return CBORObject.FromObjectAndTag(content, tagNum.AsInt32());
        }

        private void SkipWhiteSpace()
        {
            while (char.IsWhiteSpace(_input, _offset)) _offset += 1;
        }

        private static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
