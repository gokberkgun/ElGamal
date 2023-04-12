package main;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

public class ElGamal {

	BigInteger q, g, b, h, k, s, p, sPrime;
	ArrayList<BigInteger> cyclicGroup;
	Random r = new SecureRandom();
	ArrayList<BigInteger> encrypted;
	String decrypted;
	int bits, counter;
	boolean sender, c;

	public ElGamal(int bits) {

		this.bits = bits;
		this.c = true;

	}

	//generates a new key pair
	void generateKey() {
		this.q = generatePrimeNumber(this.bits);
		this.g = generator(this.q);
		this.b = SecretKeyGenerator(q);
		this.h = generatePublicKey(this.g,this.b);
		this.cyclicGroup = generateCyclicGroup(this.q, this.g);
	}

	//generates q with the given bit size
	BigInteger generatePrimeNumber(int bits) {
		q = BigInteger.probablePrime(bits, r);
		return q;
	}

	//generates random generator g for cyclic group
	BigInteger generator(BigInteger q) {		
		g = new BigInteger(q.bitLength(), r);
		if (g.compareTo(q.subtract(BigInteger.ONE)) == 1) {
			generator(q);
		}
		if (g.compareTo(BigInteger.TWO) == -1) {
			generator(q);
		}
		return g;
	}

	//generates the secret key b
	BigInteger SecretKeyGenerator(BigInteger q) {
		b = new BigInteger(q.bitLength(), r);
		if (b.compareTo(q) == 1) {
			SecretKeyGenerator(q);
		} 
		if (b.compareTo(BigInteger.TWO) == -1) {
			SecretKeyGenerator(q);
		}

		if (b.compareTo(q) == 0) {
			SecretKeyGenerator(q);
		}
		return b;
	}

	//generates the public key h
	BigInteger generatePublicKey(BigInteger g, BigInteger b) {
		h = g.pow(b.intValue());
		return h;
	}

	//generates the cyclic group 
	ArrayList<BigInteger> generateCyclicGroup(BigInteger q, BigInteger g) {
		BigInteger x = q.subtract(BigInteger.ONE);
		BigInteger i;
		ArrayList<BigInteger> cyclicGroup = new ArrayList<>();
		for (i = BigInteger.ONE ; i.compareTo(x) == -1 ; i = i.add(BigInteger.ONE)) {
			BigInteger y = g.modPow(i, q);
			cyclicGroup.add(y);
			if (y.compareTo(BigInteger.ONE) == 0) {
				break;
			}
		}
		return cyclicGroup;
	}

	//encode as transforming bytes to ascii integers
	ArrayList<BigInteger> encrypt(String message, BigInteger q, BigInteger h, BigInteger g, ArrayList<BigInteger> cyclicGroup) {
		this.k = cyclicGroup.get(r.nextInt(cyclicGroup.size()));
		this.s = h.modPow(k, q);
		this.p = g.pow(k.intValue());
		int i;
		ArrayList<BigInteger> encrypted = new ArrayList<>();
		for (i=0 ; i<message.length() ; i++) {
			int ascii = message.charAt(i);
			BigInteger ascii1 = BigInteger.valueOf(ascii);
			BigInteger encrypted1 = s.multiply(ascii1);
			encrypted.add(encrypted1);
		}

		return encrypted;
	}

	//decode as transforming ascii integers to string
	String decrypt(ArrayList<BigInteger> encrypted, BigInteger q, BigInteger b, BigInteger p) {
		sPrime = p.modPow(b, q);
		decrypted = "";
		int i;
		for (i=0 ; i<encrypted.size() ; i++) {
			decrypted +=(char) (encrypted.get(i).divide(sPrime).intValue());
		}
		return decrypted;
	}


	//this method converts the cyclicGroup variable read from the server.txt file in string format to arraylist format
	ArrayList<BigInteger> convertToArray(String str) {
		String[] stringA = str.split(", ");
		List<String> stringAL = Arrays.asList(stringA);
		ArrayList<BigInteger> bigintegerAL = new ArrayList<>();

		int i;
		for (i = 0 ; i < stringAL.size(); i++) {
			BigInteger temp = new BigInteger(stringAL.get(i));
			bigintegerAL.add(temp);
		}

		return bigintegerAL;


	}

	//writes the key and message to server.txt
	void writeMessage(File server, BigInteger p, ArrayList<BigInteger> encrypted) throws IOException {
		FileWriter w = new FileWriter(server, true);
		w.write("\nP: "+ p+"\n");
		w.write(encrypted.toString());
		w.close();
	}

	//writes the key to server.txt
	void writeKey(File server, ArrayList<BigInteger> f, BigInteger h, BigInteger q, BigInteger g) throws IOException {
		FileWriter w = new FileWriter(server, true);
		w.write("F: "+ f+"\n");
		w.write("H: " + h+"\n");
		w.write("Q: " + q+"\n");
		w.write("G: " + g);
		w.close();
	}

	//deletes every line in the server.txt to write the new key
	void formatFile(File server) throws FileNotFoundException {
		PrintWriter writer = new PrintWriter(server);
		writer.print("");
		writer.close();
	}

	//handles the communication process between two terminals
	void chat(File server, ElGamal elGamal) throws IOException {

		Scanner sc = new Scanner(server);
		ArrayList<String> a = new ArrayList<>();
		while (sc.hasNextLine()) {
			a.add(sc.nextLine());
		}
		sc.close();

		if (a.size() == 4) {

			ArrayList<BigInteger> cyclicGroupR = elGamal.convertToArray(a.get(0).substring(4,a.get(0).length()-1));
			BigInteger hR = new BigInteger(a.get(1).substring(3));
			BigInteger qR = new BigInteger(a.get(2).substring(3));
			BigInteger gR = new BigInteger(a.get(3).substring(3));

			if (elGamal.sender == true) {
				Scanner ask = new Scanner(System.in);
				System.out.print("Press '1' if you want to send a message or press '2' if you want to end communication: ");
				int reply = ask.nextInt();
				while (reply != 1 && reply!=2) {
					System.out.print("Invalid input. Press '1' if you want to send a message or press '2' if you want to end communication: ");
					reply = ask.nextInt();
				}
				if (reply == 1) {
					Scanner inputMessage = new Scanner(System.in);
					System.out.print("Please enter the message you want to send: ");
					String message = inputMessage.nextLine();
					ArrayList<BigInteger> encryptedAL = elGamal.encrypt(message, qR, hR, gR, cyclicGroupR);
					elGamal.writeMessage(server, elGamal.p, encryptedAL);
					System.out.println("Message sent.");
					elGamal.counter -= 1;
				} else if (reply == 2) {
					elGamal.c = false;
					elGamal.formatFile(server);
				}
			}


		} else if (a.size() == 6 && elGamal.sender == false) {

			BigInteger qR = new BigInteger(a.get(2).substring(3));
			BigInteger pR = new BigInteger(a.get(4).substring(3));
			ArrayList<BigInteger> encrypted = elGamal.convertToArray(a.get(5).substring(1,a.get(5).length()-1));

			String decryptedMessage = elGamal.decrypt(encrypted, qR, elGamal.b, pR);
			System.out.println("New message received.");
			System.out.println("********************");
			System.out.println(decryptedMessage);
			System.out.println("********************");
			elGamal.sender = true;
			elGamal.formatFile(server);
			elGamal.counter += 1;

		}

		if (elGamal.sender == true && (elGamal.counter % 2 == 1) && server.length() == 0) {
			elGamal.sender = false;
			elGamal.generateKey();
			elGamal.formatFile(server);

			if (server.length() == 0) {
				elGamal.writeKey(server, elGamal.cyclicGroup, elGamal.h, elGamal.q, elGamal.g);
			}

		} else if (elGamal.sender == false && server.length() == 0) {
			elGamal.c = false;
		}
	}

	public static void main(String[] args) throws IOException, InterruptedException {


		//since it takes a lot of time to generate a cyclic group with biginteger of 160 bits, i made the bit value changeable to test in shorter time. 
		int bitSize = 8;

		File server = new File(args[0]);
		ElGamal elGamal = new ElGamal(bitSize);


		//the first terminal opened is always the first receiver
		if (server.length() == 0) {
			System.out.println("Welcome! Your current status is receiver. Please wait for a message from the sender. ");
			elGamal.generateKey();
			elGamal.writeKey(server, elGamal.cyclicGroup, elGamal.h, elGamal.q, elGamal.g);
			elGamal.sender = false;
			elGamal.counter = 1;

		} else {
			System.out.println("Welcome! Your current status is sender. ");
			elGamal.sender = true;
			elGamal.counter = 2;
		}

		while (true) {

			elGamal.chat(server, elGamal);
			
			Thread.sleep(5000);
			
			if (elGamal.c == false) {
				System.out.println("Session has been terminated.");
				break;
			}

		}

	}

}




