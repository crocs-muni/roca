/*
 * Based on JAVA code created by Martin Paljak available at 
 * https://github.com/crocs-muni/roca/blob/33d0344346ad6f6802ae3803a0e0e501eb06a024/java/BrokenKey.java
 */

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace RocaTest
{
    public static class RocaTest
    {
        private static BigInteger[] markers = new BigInteger[]{
            new BigInteger("6"),
            new BigInteger("30"),
            new BigInteger("126"),
            new BigInteger("1026"),
            new BigInteger("5658"),
            new BigInteger("107286"),
            new BigInteger("199410"),
            new BigInteger("8388606"),
            new BigInteger("536870910"),
            new BigInteger("2147483646"),
            new BigInteger("67109890"),
            new BigInteger("2199023255550"),
            new BigInteger("8796093022206"),
            new BigInteger("140737488355326"),
            new BigInteger("5310023542746834"),
            new BigInteger("576460752303423486"),
            new BigInteger("1455791217086302986"),
            new BigInteger("147573952589676412926"),
            new BigInteger("20052041432995567486"),
            new BigInteger("6041388139249378920330"),
            new BigInteger("207530445072488465666"),
            new BigInteger("9671406556917033397649406"),
            new BigInteger("618970019642690137449562110"),
            new BigInteger("79228162521181866724264247298"),
            new BigInteger("2535301200456458802993406410750"),
            new BigInteger("1760368345969468176824550810518"),
            new BigInteger("50079290986288516948354744811034"),
            new BigInteger("473022961816146413042658758988474"),
            new BigInteger("10384593717069655257060992658440190"),
            new BigInteger("144390480366845522447407333004847678774"),
            new BigInteger("2722258935367507707706996859454145691646"),
            new BigInteger("174224571863520493293247799005065324265470"),
            new BigInteger("696898287454081973172991196020261297061886"),
            new BigInteger("713623846352979940529142984724747568191373310"),
            new BigInteger("1800793591454480341970779146165214289059119882"),
            new BigInteger("126304807362733370595828809000324029340048915994"),
            new BigInteger("11692013098647223345629478661730264157247460343806"),
            new BigInteger("187072209578355573530071658587684226515959365500926")
        };

        private static int[] prims = new int[] { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167 };

        private static BigInteger[] primes = new BigInteger[prims.Length];

        static RocaTest()
        {
            for (int i = 0; i < prims.Length; i++)
            {
                primes[i] = BigInteger.ValueOf(prims[i]);
            }
        }

        public static bool IsVulnerable(RsaKeyParameters rsaKey)
        {
            if (rsaKey == null)
                return false;

            for (int i = 0; i < primes.Length; i++)
            {
                if (BigInteger.One.ShiftLeft(rsaKey.Modulus.Remainder(primes[i]).IntValue).And(markers[i]).Equals(BigInteger.Zero))
                {
                    return false;
                }
            }

            return true;
        }
    }
}
