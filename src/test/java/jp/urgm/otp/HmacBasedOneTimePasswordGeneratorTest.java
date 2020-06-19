package jp.urgm.otp;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class HmacBasedOneTimePasswordGeneratorTest {

	private static HmacBasedOneTimePasswordGenerator generator;

	private static byte[] key;

	@BeforeAll
	static void init() {
		generator = HmacBasedOneTimePasswordGenerator
				.builder()
				.algorithm("HmacSHA1")
				.digit(6)
				.build();

		//Secret = 0x3132333435363738393031323334353637383930
		key = new byte[20];
		int index = 0;
		for (int i = 0; i < 2; i++) {
			for (byte b = 0x31; b <= 0x39; b++) {
				key[index++] = b;
			}
			key[index++] = 0x30;
		}
	}

	@ParameterizedTest
	@CsvSource(value = {
			"0 | 755224",
			"1 | 287082",
			"2 | 359152",
			"3 | 969429",
			"4 | 338314",
			"5 | 254676",
			"6 | 287922",
			"7 | 162583",
			"8 | 399871",
			"9 | 520489",
	}, delimiter = '|')
	void generate(long counter, int expected) throws Exception {
		assertEquals(expected, generator.generate(key, counter));
	}
}
