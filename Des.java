import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.BitSet;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;


public class Des {









    public static byte[] des_attack(String plaintext , byte[] encoded_key2,int N_BYTE) throws Exception
    {

        byte[] encoded_key =new byte []{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }; //My key eoncoded
        for (int i=0;i<N_BYTE;i++) encoded_key[8-N_BYTE+i]=encoded_key2[i];

            SecretKey key = new SecretKeySpec(encoded_key, "DES"); // Creates secret key

        // Initialization vector for cbc
        byte[] initVector = new byte[] { 0x10, 0x10, 0x01, 0x04, 0x01, 0x01, 0x01, 0x02 };
        AlgorithmParameterSpec algParamSpec = new IvParameterSpec(initVector);

        //Cypher for  encryption
        Cipher m_encrypter = Cipher.getInstance("DES/CBC/PKCS5Padding");
        m_encrypter.init(Cipher.ENCRYPT_MODE, key, algParamSpec);


        //Cypher for decryption_attack
        Cipher m_decrypter = Cipher.getInstance("DES/CBC/PKCS5Padding");

        //Plain text
        byte[] clearText = plaintext.getBytes();

        //Cyphertext
        byte[] encryptedText = m_encrypter.doFinal(clearText);


        int guess=0;
        //int N_BYTE=5;
        int N_COMB = (int)Math.pow(2.0,(N_BYTE)*7);
        System.out.println("N. of all possible combiantions : " +N_COMB);

        //key_encoding for attack
        BitSet encoding_attack_key = new BitSet(8*N_BYTE);
        encoding_attack_key.clear();
        byte[] mykey =new byte[] {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

        long startTime = System.nanoTime();


        for (int i=0;i<N_COMB;i++){

            String tmp = Integer.toBinaryString(i);

            int z=0;
            int j=tmp.length()-1;
            while (j>=0){

                if (z!=63&&z!=55&&z!=47&&z!=39&&z!=31&&z!=23&&z!=15&&z!=7) {
                    if (tmp.charAt(j) == '1') {
                        encoding_attack_key.set(z);


                    }
                    j--;
                    z++;
                } else {
                    z++;
                }

            }


            for (int k=0;k<N_BYTE;k++){

                if ( encoding_attack_key.get( k*8  ,   (k*8)+7).cardinality() %2 != 0 ){

                    encoding_attack_key.set((k*8)+7);

                }
            }

            if (guess%1000000==0){
                System.out.println("Guess n : " +guess +" out of : "+N_COMB + " ------- " + 100*(guess+0.0)/N_COMB +"% completed");

            }
            guess++;



            int len=encoding_attack_key.toByteArray().length;
            mykey[0]=len>=8?encoding_attack_key.toByteArray()[7]:0x0;
            mykey[1]=len>=7?encoding_attack_key.toByteArray()[6]:0x0;
            mykey[2]=len>=6?encoding_attack_key.toByteArray()[5]:0x0;
            mykey[3]=len>=5?encoding_attack_key.toByteArray()[4]:0x0;
            mykey[4]=len>=4?encoding_attack_key.toByteArray()[3]:0x0;
            mykey[5]=len>=3?encoding_attack_key.toByteArray()[2]:0x0;
            mykey[6]=len>=2?encoding_attack_key.toByteArray()[1]:0x0;
            mykey[7]=len>=1?encoding_attack_key.toByteArray()[0]:0x0;






            SecretKey key_g = new SecretKeySpec(mykey, "DES");
            m_decrypter.init(Cipher.DECRYPT_MODE, key_g, algParamSpec);
            try{
                byte[] text_g = m_decrypter.doFinal(encryptedText);
                String plain_text=new String(text_g);

                if (plain_text.equals(new String(clearText))){
                    long  estimatedTime = (System.nanoTime() - startTime);
                    //System.out.println("Found key with string comparison : "+BitSet.valueOf(mykey).toString() + " , time requested in nanoseconds: "+estimatedTime);
                    return mykey;




                }

            }
            catch (BadPaddingException ee){

            }

            encoding_attack_key.clear();





        }
        return null;
    }

    public static void main(String args[]) throws Exception
    {

        String plaintext="vbnnbhgjhyuiu";
        int nbyte=4;
        byte[] b=new byte[]{0x4,0x12,0x65,0x06};



        long startTime = System.nanoTime();

        byte []ris=des_attack(plaintext,b,b.length);
        long  estimatedTime = (System.nanoTime() - startTime);

        String kris="";
        for (int i=0;i<ris.length;i++) kris+=" "+ris[i]+" ";
        System.out.println("PLAINTEXT : "+plaintext+"      ESTIMATED TIME: "+estimatedTime+"     NFREE_BYTE_KEY: "+nbyte+"    KEY: "+kris+"\n");







        BufferedWriter bw = null;
        try {
            File file = new File("test1.txt");
            FileWriter fileWriter = new FileWriter(file,true);
            fileWriter.write("PLAINTEXT : "+plaintext+"      ESTIMATED TIME: "+estimatedTime+"     NFREE_BYTE_KEY: "+nbyte+"    KEY: "+kris+"\n");

            fileWriter.flush();
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }




}
