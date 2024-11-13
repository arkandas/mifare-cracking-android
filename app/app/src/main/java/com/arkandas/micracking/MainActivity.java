package com.arkandas.micracking;
import androidx.appcompat.app.AppCompatActivity;
import androidx.cardview.widget.CardView;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.content.Intent;
import android.graphics.Color;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.MifareUltralight;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import com.arkandas.micracking.util.CardWritterConstants;
import com.arkandas.micracking.util.HexConverter;
import java.io.IOException;
import java.nio.charset.Charset;
import static com.arkandas.micracking.util.HexConverter.hexStringToByteArray;
import static com.arkandas.micracking.util.HexConverter.toDec;

public class MainActivity extends AppCompatActivity {
    //Initialize attributes
    NfcAdapter nfcAdapter;
    PendingIntent pendingIntent;
    // TextViews
    TextView creditText;
    TextView uidData;
    TextView technologies;
    TextView sizeData;
    TextView sectorData;
    TextView blockData;
    TextView mifareType;
    TextView cardValidity;
    TextView currentTxNumber;
    TextView currentTxAmountData;
    TextView currentTxChecksum;
    TextView previousTxNumber;
    TextView previousTxAmountData;
    TextView previousTxChecksum;
    TextView cardTxMagicValue;
    TextView cardTxLastTransactionCost;
    // CardViews
    CardView CardModel;
    CardView UIDCard;
    CardView ElementSizeCard;
    CardView CardCurrentTransaction;
    CardView CardPreviousTransaction;
    CardView CardTxValues;
    // Buttons
    Button writeCardButton;

    MifareClassic scannedCard = null;

    final static String TAG = "nfc_scanner";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // TextViews
        creditText = findViewById(R.id.creditText);
        uidData = findViewById(R.id.uid_data);
        technologies = findViewById(R.id.technologies);
        sizeData = findViewById(R.id.size_data);
        sectorData = findViewById(R.id.sectors_data);
        blockData = findViewById(R.id.blocks_data);
        mifareType = findViewById(R.id.myfare_type);

        currentTxNumber = findViewById(R.id.current_tx_number_data);
        currentTxAmountData = findViewById(R.id.current_tx_amount_data);
        currentTxChecksum = findViewById(R.id.current_tx_checksum_data);

        previousTxNumber = findViewById(R.id.previous_tx_number_data);
        previousTxAmountData = findViewById(R.id.previous_tx_amount_data);
        previousTxChecksum = findViewById(R.id.previous_tx_checksum_data);

        cardTxMagicValue = findViewById(R.id.card_tx_values_magic_data);
        cardTxLastTransactionCost = findViewById(R.id.card_tx_values_last_tx_cost_data);
        cardValidity = findViewById(R.id.card_validity);
        // Buttons
        writeCardButton = findViewById(R.id.write_card_button);
        // Card Views
        UIDCard = findViewById(R.id.card_element);
        ElementSizeCard = findViewById(R.id.card_element_sizes);
        CardCurrentTransaction = findViewById(R.id.card_current_tx);
        CardPreviousTransaction = findViewById(R.id.card_previous_tx);
        CardTxValues = findViewById(R.id.card_tx_values);
        CardModel = findViewById(R.id.card_model);
        // Card Views Visibility
        UIDCard.setVisibility(View.GONE);
        ElementSizeCard.setVisibility(View.GONE);
        CardCurrentTransaction.setVisibility(View.GONE);
        CardPreviousTransaction.setVisibility(View.GONE);
        CardTxValues.setVisibility(View.GONE);
        writeCardButton.setVisibility(View.GONE);

        // Set button listener
        writeCardButton.setOnClickListener(v -> {
            writeToCard(scannedCard);
        });

        //Initialise NfcAdapter
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        //If no NfcAdapter, display that the device has no NFC
        if (nfcAdapter == null) {
            Toast.makeText(this, "NO NFC Capabilities",
                    Toast.LENGTH_SHORT).show();
            finish();
        }
        pendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, this.getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
    }

    @Override
    protected void onResume() {
        super.onResume();
        assert nfcAdapter != null;
        nfcAdapter.enableForegroundDispatch(this, pendingIntent, null, null);
    }

    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null) {
            nfcAdapter.disableForegroundDispatch(this);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        resolveIntent(intent);
    }

    private void resolveIntent(Intent intent) {
        String action = intent.getAction();
        if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(action) || NfcAdapter.ACTION_TECH_DISCOVERED.equals(action) || NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action)) {
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            assert tag != null;
            detectTagData(tag).getBytes();
        }
    }

    // Tag detection
    private String detectTagData(Tag tag) {
        StringBuilder sb = new StringBuilder();
        byte[] id = tag.getId();

        String cardUidReverseHex = HexConverter.toReversedHex(id);
        uidData.setText(cardUidReverseHex);
        UIDCard.setVisibility(View.VISIBLE);

        String prefix = "android.nfc.tech.";
        sb.append("Technologies: ");
        StringBuilder techString = new StringBuilder();
        for (String tech : tag.getTechList()) {
            techString.append(tech.substring(prefix.length()));
            techString.append(", ");
        }
        techString.delete(techString.length() - 2, techString.length());
        technologies.setText(techString);

        for (String tech : tag.getTechList()) {
            if (tech.equals(MifareClassic.class.getName())) {
                sb.append('\n');
                String type = "Unknown";
                try {
                    MifareClassic mifareTag = MifareClassic.get(tag);

                    switch (mifareTag.getType()) {
                        case MifareClassic.TYPE_CLASSIC:
                            type = "Classic";
                            break;
                        case MifareClassic.TYPE_PLUS:
                            type = "Plus";
                            break;
                        case MifareClassic.TYPE_PRO:
                            type = "Pro";
                            break;
                    }
                    mifareType.setTextColor(Color.parseColor("#ffa45b"));
                    mifareType.setText("Mifare type: " + type);
                    sizeData.setText(mifareTag.getSize() + " bytes");
                    sectorData.setText(String.valueOf(mifareTag.getSectorCount()));
                    blockData.setText(String.valueOf(mifareTag.getBlockCount()));
                    ElementSizeCard.setVisibility(View.VISIBLE);
                    // Check card uid -> Add your uid here
                     if(cardUidReverseHex.equals("XX XX XX XX")){
                        scannedCard = MifareClassic.get(tag);
                        getCardInfo(scannedCard);
                    }else {
                        resetCard(scannedCard);
                    }

                } catch (Exception e) {
                    sb.append("Mifare classic error: " + e.getMessage());
                }
            }

            if (tech.equals(MifareUltralight.class.getName())) {
                sb.append('\n');
                MifareUltralight mifareUlTag = MifareUltralight.get(tag);
                String type = "Unknown";
                switch (mifareUlTag.getType()) {
                    case MifareUltralight.TYPE_ULTRALIGHT:
                        type = "Ultralight";
                        break;
                    case MifareUltralight.TYPE_ULTRALIGHT_C:
                        type = "Ultralight C";
                        break;
                }
                mifareType.setText("Mifare Ultralight type: " + type);
            }
        }
        Log.v(TAG,sb.toString());
        return sb.toString();
    }

    private void getCardInfo(MifareClassic mifareClassic) throws IOException {
        mifareClassic.connect();
        boolean authSect9A = mifareClassic.authenticateSectorWithKeyA(9, hexStringToByteArray(CardWritterConstants.SectorKeyA));
        boolean authSect9B = mifareClassic.authenticateSectorWithKeyB(9, hexStringToByteArray(CardWritterConstants.SectorKeyB));
        String highLow = "";
        if (authSect9A && authSect9B) {
            byte[] b0Sect9 = mifareClassic.readBlock(36);
            highLow = String.format("%02X", b0Sect9[0]);
        }

        boolean authSect10A = mifareClassic.authenticateSectorWithKeyA(10, hexStringToByteArray(CardWritterConstants.SectorKeyA));
        boolean authSect10B = mifareClassic.authenticateSectorWithKeyB(10, hexStringToByteArray(CardWritterConstants.SectorKeyB));
        if (authSect10A && authSect10B) {
            byte[] b1Sect10;
            byte[] b2Sect10;
            if(highLow.equals("3A")) {
                b1Sect10 = mifareClassic.readBlock(41);
                b2Sect10 = mifareClassic.readBlock(42);
            }else if (highLow.equals("C5")){
                b1Sect10 = mifareClassic.readBlock(42);
                b2Sect10 = mifareClassic.readBlock(41);
            }else {
                b1Sect10 = mifareClassic.readBlock(41);
                b2Sect10 = mifareClassic.readBlock(42);
            }

            if(b1Sect10 != null && b2Sect10 != null) {

                Long currentCredit = Long.parseLong(HexConverter.bytesToHex(new byte[]{b1Sect10[4], b1Sect10[5]}), 16);
                Long pastCredit = Long.parseLong(HexConverter.bytesToHex(new byte[]{b2Sect10[4], b2Sect10[5]}), 16);

                // Current transaction
                currentTxNumber.setText(String.valueOf(Long.parseLong(HexConverter.bytesToHex(new byte[]{b1Sect10[0], b1Sect10[1]}), 16)));
                currentTxAmountData.setText(String.format("%.2f", Double.valueOf(currentCredit) / 100) + " €");
                currentTxChecksum.setText(HexConverter.bytesToHex(new byte[]{b1Sect10[6], b1Sect10[7]}));
                CardCurrentTransaction.setVisibility(View.VISIBLE);
                // Previous transaction
                previousTxNumber.setText(String.valueOf(Long.parseLong(HexConverter.bytesToHex(new byte[]{b2Sect10[0], b2Sect10[1]}), 16)));
                previousTxAmountData.setText(String.format("%.2f", Double.valueOf(pastCredit) / 100) + " €");
                previousTxChecksum.setText(HexConverter.bytesToHex(new byte[]{b2Sect10[6], b2Sect10[7]}));
                CardPreviousTransaction.setVisibility(View.VISIBLE);
                // Transaction Magic Info
                cardTxMagicValue.setText(highLow);
                cardTxLastTransactionCost.setText(String.format("%.2f", Double.valueOf(currentCredit-pastCredit) / 100) + " €");
                CardTxValues.setVisibility(View.VISIBLE);
                // Version Text
                CardModel.setBackgroundResource(R.drawable.card_view_border);
                creditText.setTextSize(45);
                creditText.setTextColor(Color.parseColor("#ffa45b"));
                creditText.setText(String.format("Balance: %s €", String.format("%.2f", Double.valueOf(currentCredit) / 100)));
                cardValidity.setTextColor(Color.parseColor("#ffa45b"));
                cardValidity.setText("Valid Card");
                writeCardButton.setVisibility(View.VISIBLE);
                mifareClassic.close();
            } else {
               resetCard(mifareClassic);
            }
        }
    }

    private void resetCard(MifareClassic mifareClassic) throws IOException {
        cardValidity.setTextColor(Color.RED);
        cardValidity.setText("Invalid Card");
        mifareType.setTextColor(Color.BLACK);
        creditText.setTextColor(Color.BLACK);
        creditText.setTextSize(40);
        creditText.setText("Unknown Balance");
        CardModel.setBackgroundResource(R.drawable.card_view_invalid);
        CardCurrentTransaction.setVisibility(View.GONE);
        CardPreviousTransaction.setVisibility(View.GONE);
        CardTxValues.setVisibility(View.GONE);
        writeCardButton.setVisibility(View.GONE);
        mifareClassic.close();
    }

    private void writeToCard(MifareClassic mifareClassic){
        try {
            mifareClassic.connect();
            // Write Sector 9
            boolean sect09KeyA = mifareClassic.authenticateSectorWithKeyA(9, hexStringToByteArray(CardWritterConstants.SectorKeyA));
            boolean sect09KeyB = mifareClassic.authenticateSectorWithKeyB(9, hexStringToByteArray(CardWritterConstants.SectorKeyB));
            if (sect09KeyA && sect09KeyB) {
                mifareClassic.writeBlock(36, hexStringToByteArray(CardWritterConstants.Sector9Block0));
                mifareClassic.writeBlock(37, hexStringToByteArray(CardWritterConstants.Sector9Block1));
                mifareClassic.writeBlock(38, hexStringToByteArray(CardWritterConstants.Sector9Block2));
            }
            // Write Sector 10
            boolean sect10KeyA = mifareClassic.authenticateSectorWithKeyA(10, hexStringToByteArray(CardWritterConstants.SectorKeyA));
            boolean sect10KeyB = mifareClassic.authenticateSectorWithKeyB(10, hexStringToByteArray(CardWritterConstants.SectorKeyB));
            if (sect10KeyB && sect10KeyA) {
                mifareClassic.writeBlock(40, hexStringToByteArray(CardWritterConstants.Sector10Block0));
                mifareClassic.writeBlock(41, hexStringToByteArray(CardWritterConstants.Sector10Block1));
                mifareClassic.writeBlock(42, hexStringToByteArray(CardWritterConstants.Sector10Block2));
            }
            // Write Sector 11
            boolean sect11KeyA = mifareClassic.authenticateSectorWithKeyA(11, hexStringToByteArray(CardWritterConstants.SectorKeyA));
            boolean sect11KeyB = mifareClassic.authenticateSectorWithKeyB(11, hexStringToByteArray(CardWritterConstants.SectorKeyB));
            if (sect11KeyA && sect11KeyB) {
                mifareClassic.writeBlock(44, hexStringToByteArray(CardWritterConstants.Sector11Block0));
            }
//                byte[] checkBlock40 = mifareClassic.readBlock(41);
//                byte[] checkBlock41 = mifareClassic.readBlock(41);
//                byte[] checkBlock42 = mifareClassic.readBlock(41);
//                if(!HexConverter.bytesToHex(checkBlock40).equals(CardWritterConstants.Sector10Block0)){
//                    Log.e(TAG, "Error writing to block 40");
//                }
//                if(!HexConverter.bytesToHex(checkBlock41).equals(CardWritterConstants.Sector10Block1)){
//                    Log.e(TAG, "Error writing to block 41");
//                }
//                if(!HexConverter.bytesToHex(checkBlock42).equals(CardWritterConstants.Sector10Block2)){
//                    Log.e(TAG, "Error writing to block 42");
//                }

            Toast.makeText(this, "Balance Updated!",
                    Toast.LENGTH_SHORT).show();
        } catch (IOException e) {
            Log.e(TAG, "IOException while writing MifareClassic...", e);
            Toast.makeText(this, "Error Updating Balance!",
                    Toast.LENGTH_SHORT).show();
        } finally {
            try {
                mifareClassic.close();
            } catch (IOException e) {
                Log.e(TAG, "IOException while closing MifareClassic...", e);
            }
        }
    }

}



