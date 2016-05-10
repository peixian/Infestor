void key_expand(char key[16], char outKey[32])
{
	for (int i = 0; i < 16; ++i) {
		unsigned char uc = key[i];
		outKey[i * 2 + 0] = uc + 0x7A; // uc + "z"
	}
	
}