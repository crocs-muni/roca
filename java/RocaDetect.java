

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;


public class RocaDetect
{
	
	private static final BigInteger primorial = new BigInteger( "962947420735983927056946215901134429196419130606213075415963491270" );
	
	private static final BigInteger generatorOrder = new BigInteger( "2454106387091158800" );
	
	private static final BigInteger[][] precomputed = { //
		{ new BigInteger( "16" ), new BigInteger( "153381649193197425" ), new BigInteger( "579701604149392295790310832658859347575600566378196268451889670917" ) }, //
		{ new BigInteger( "81" ), new BigInteger( "30297609717174800" ), new BigInteger( "277722225047912451353908303068039414108454325703031162502745467431" ) }, //
		{ new BigInteger( "25" ), new BigInteger( "98164255483646352" ), new BigInteger( "234201887969172179017831590126685452395189736370272535972311924721" ) }, //
		{ new BigInteger( "7" ), new BigInteger( "350586626727308400" ), new BigInteger( "465795348279120036271926818215675896518889071711237747055072416431" ) }, //
		{ new BigInteger( "11" ), new BigInteger( "223100580644650800" ), new BigInteger( "437012106259973544013288076253697869776983569163405597124590041661" ) }, //
		{ new BigInteger( "13" ), new BigInteger( "188777414391627600" ), new BigInteger( "600233314679500130765997367568070397728989341087574577462488273851" ) }, //
		{ new BigInteger( "17" ), new BigInteger( "144359199240656400" ), new BigInteger( "490583871282757313557677439310697711820073497975201318061467049731" ) }, //
		{ new BigInteger( "23" ), new BigInteger( "106700277699615600" ), new BigInteger( "898534743120550745345039665105359785761728305552651906893573158241" ) }, //
		{ new BigInteger( "29" ), new BigInteger( "84624358175557200" ), new BigInteger( "48963428173016131884251502503447513348970464268112529258438821591" ) }, //
		{ new BigInteger( "37" ), new BigInteger( "66327199651112400" ), new BigInteger( "652736171102915279414440052389359579522404914035084030986659816231" ) }, //
		{ new BigInteger( "41" ), new BigInteger( "59856253343686800" ), new BigInteger( "452469269984377989821938583375231840224823446911353131821958748911" ) }, //
		{ new BigInteger( "53" ), new BigInteger( "46303894096059600" ), new BigInteger( "341981326990349432038915478544328115041718943579776606222491707181" ) }, //
		{ new BigInteger( "83" ), new BigInteger( "29567546832423600" ), new BigInteger( "651575200857282537469670193992983176641888393763485494143735775531" ) } //
	};
	
	
	public static final boolean isVulnerable( PublicKey publicKey )
	{
		if ( ! ( publicKey instanceof RSAPublicKey ) )
			return false;
		return isVulnerable( ( (RSAPublicKey) publicKey ).getModulus() );
	}
	
	
	public static final boolean isVulnerable( BigInteger modulus )
	{
		if ( ! modulus.modPow( generatorOrder, primorial ).equals( BigInteger.ONE ) )
			return false;
		outer: for ( BigInteger[] array : precomputed ) {
			BigInteger primeToPower = array[ 0 ]; // factorPower.factor.pow( factorPower.power )
			BigInteger orderDivPrimePower = array[ 1 ]; // generatorOrder.divide( primeToPower ); // g.div(generator_order, prime_to_power)
			BigInteger generatorDash = array[ 2 ]; // generator.modPow( orderDivPrimePower, primorial );
			BigInteger modulusDash = modulus.modPow( orderDivPrimePower, primorial );
			if ( modulusDash.equals( BigInteger.ONE ) )
				continue outer;
			BigInteger generatorDashToI = generatorDash;
			for ( int i = 1, max = primeToPower.intValueExact(); i < max; i ++ , generatorDashToI = generatorDashToI.multiply( generatorDash ).mod( primorial ) )
				if ( generatorDashToI.equals( modulusDash ) )
					continue outer;
			return false;
		}
		return true;
	}
	
}
