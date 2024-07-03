//-----------------------------------------------------------
// Author: Nguyen Hung Quan
// Website: http://nguyenquanicd.blogspot.com/
//-----------------------------------------------------------
module aes128_cipher_core(
  //input
  input clk_sys,
  input rst_n,
  input	[127:0]	cipher_key,
  input	[127:0]	round_key,
  input	[127:0]	plain_text,
  input cipher_en,
  //output
  output logic [127:0] cipher_text,
  output logic cipher_ready,
  output logic [3:0] round_num,
  output logic rkey_en 
  );
  //All internal signals
  logic	[127:0]	after_mixColumns;
  logic	[127:0]	subbytes_sel;
  logic [127:0]	after_shiftRows;
  logic [127:0]	cipherText_reg;
  logic	[127:0]	mixColumns_in;
  logic [127:0]	after_subBytes;
  logic [127:0] addRoundKey_in;
  logic [127:0] after_addRoundkey;
  logic [3:0]	cipher_counter;
  logic		cipher_complete;
  //Monitor counter
 function logic [7:0] mul2;
  input [7:0] mul2_in;
  mul2[7:0] = (mul2_in[7] == 1'b1)?
              ({mul2_in[6:0], 1'b0} ^ 8'b0001_1011)
  				    : {mul2_in[6:0], 1'b0};
endfunction
//
function logic [7:0] mul3;
  input [7:0] mul3_in;
  mul3[7:0] = mul2(mul3_in[7:0]) ^ mul3_in[7:0];
endfunction
//Multiplication of the MixColumns matrix and a column of state matrix
function logic [31:0] mixcol;
  input [31:0] mixcol_in;
  mixcol[31:24] = mul2(mixcol_in[31:24]) ^ mul3(mixcol_in[23:16]) ^ mixcol_in[15:8]       ^ mixcol_in[7:0];
  mixcol[23:16] = mixcol_in[31:24]       ^ mul2(mixcol_in[23:16]) ^ mul3(mixcol_in[15:8]) ^ mixcol_in[7:0];
  mixcol[15:8]  = mixcol_in[31:24]       ^ mixcol_in[23:16]       ^ mul2(mixcol_in[15:8]) ^ mul3(mixcol_in[7:0]);
  mixcol[7:0]   = mul3(mixcol_in[31:24]) ^ mixcol_in[23:16]       ^ mixcol_in[15:8]       ^ mul2(mixcol_in[7:0]);
endfunction
function logic [31:0] aes128_rcon;
  input [3:0] rkey_sel;
	case (rkey_sel)
		4'd0:	aes128_rcon[31:0] = 32'h0100_0000;
		4'd1:	aes128_rcon[31:0] = 32'h0200_0000;
		4'd2:	aes128_rcon[31:0] = 32'h0400_0000;
		4'd3:	aes128_rcon[31:0] = 32'h0800_0000;
		4'd4:	aes128_rcon[31:0] = 32'h1000_0000;
		4'd5:	aes128_rcon[31:0] = 32'h2000_0000;
		4'd6:	aes128_rcon[31:0] = 32'h4000_0000;
		4'd7:	aes128_rcon[31:0] = 32'h8000_0000;
		4'd8:	aes128_rcon[31:0] = 32'h1b00_0000;
		4'd9:	aes128_rcon[31:0] = 32'h3600_0000;
		default: aes128_rcon[31:0] = 32'h3600_0000;
	endcase
endfunction
function logic [1:0] mulGf22;
  input [1:0] mulGf22_in0;
  input [1:0] mulGf22_in1;
  //
  mulGf22[1] = (mulGf22_in0[1] & mulGf22_in1[1])
             ^ (mulGf22_in0[0] & mulGf22_in1[1])
             ^ (mulGf22_in0[1] & mulGf22_in1[0]);
  //           
  mulGf22[0] = (mulGf22_in0[1] & mulGf22_in1[1])
             ^ (mulGf22_in0[0] & mulGf22_in1[0]);
endfunction

//-----------------------------------------------------
// Multiple 2 operands in GF(2^4)
//-----------------------------------------------------
function logic [3:0] mulGf24;
  input [3:0] operand0;
  input [3:0] operand1;
  //
  logic [1:0] operand0_msb;
  logic [1:0] operand0_lsb;
  logic [1:0] operand1_msb;
  logic [1:0] operand1_lsb;
  logic [1:0] operand0_xor;
  logic [1:0] operand1_xor;
  logic [1:0] mul_msb0_msb1;
  logic [1:0] mul_xor0_xor1;
  logic [1:0] mul_lsb0_lsb1;
  logic [1:0] xPhi;
  //
  operand0_msb[1:0] = operand0[3:2];
  operand0_lsb[1:0] = operand0[1:0];
  operand1_msb[1:0] = operand1[3:2];
  operand1_lsb[1:0] = operand1[1:0];
  //XOR IN
  operand0_xor[1:0] = operand0_msb[1:0] ^ operand0_lsb[1:0];
  operand1_xor[1:0] = operand1_msb[1:0] ^ operand1_lsb[1:0];
  //Multiplication
  mul_msb0_msb1[1:0] = mulGf22(operand0_msb, operand1_msb);
  mul_xor0_xor1[1:0] = mulGf22(operand0_xor, operand1_xor);
  mul_lsb0_lsb1[1:0] = mulGf22(operand0_lsb, operand1_lsb);
  //x Phi
  xPhi[1] = mul_msb0_msb1[1] ^ mul_msb0_msb1[0];
  xPhi[0] = mul_msb0_msb1[1];
  //XOR OUT
  mulGf24[3:2] = mul_xor0_xor1[1:0] ^ mul_lsb0_lsb1[1:0];
  mulGf24[1:0] = xPhi[1:0]          ^ mul_lsb0_lsb1[1:0];
endfunction
//-----------------------------------------------------
// Affine transformation
//-----------------------------------------------------
function logic [7:0] affine;
  input [7:0] after_mulInv;
  //
  affine[0] = after_mulInv[0]
            ^ after_mulInv[4]
            ^ after_mulInv[5]
            ^ after_mulInv[6]
            ^ after_mulInv[7]
            ^ 1'b1;

  affine[1] = after_mulInv[0]
            ^ after_mulInv[1]
            ^ after_mulInv[5]
            ^ after_mulInv[6]
            ^ after_mulInv[7]
            ^ 1'b1;

  affine[2] = after_mulInv[0]
            ^ after_mulInv[1]
            ^ after_mulInv[2]
            ^ after_mulInv[6]
            ^ after_mulInv[7];

  affine[3] = after_mulInv[0]
            ^ after_mulInv[1]
            ^ after_mulInv[2]
            ^ after_mulInv[3]
            ^ after_mulInv[7];

  affine[4] = after_mulInv[0]
            ^ after_mulInv[1]
            ^ after_mulInv[2]
            ^ after_mulInv[3]
            ^ after_mulInv[4];

  affine[5] = after_mulInv[1]
            ^ after_mulInv[2]
            ^ after_mulInv[3]
            ^ after_mulInv[4]
            ^ after_mulInv[5]
            ^ 1'b1;

  affine[6] = after_mulInv[2]
            ^ after_mulInv[3]
            ^ after_mulInv[4]
            ^ after_mulInv[5]
            ^ after_mulInv[6]
            ^ 1'b1;
  
  affine[7] = after_mulInv[3]
            ^ after_mulInv[4]
            ^ after_mulInv[5]
            ^ after_mulInv[6]
            ^ after_mulInv[7];
endfunction
//-----------------------------------------------------
// Inverse Affine transformation
//-----------------------------------------------------
function logic [7:0] affineInv;
  input [7:0] before_mulInv;
  //
  affineInv[0] = before_mulInv[2]
            ^ before_mulInv[5]
            ^ before_mulInv[7]
            ^ 1'b1;

  affineInv[1] = before_mulInv[0]
            ^ before_mulInv[3]
            ^ before_mulInv[6];

  affineInv[2] = before_mulInv[1]
            ^ before_mulInv[4]
            ^ before_mulInv[7]
            ^ 1'b1;

  affineInv[3] = before_mulInv[0]
            ^ before_mulInv[2]
            ^ before_mulInv[5];

  affineInv[4] = before_mulInv[1]
            ^ before_mulInv[3]
            ^ before_mulInv[6];

  affineInv[5] = before_mulInv[2]
            ^ before_mulInv[4]
            ^ before_mulInv[7];

  affineInv[6] = before_mulInv[0]
            ^ before_mulInv[3]
            ^ before_mulInv[5];
  
  affineInv[7] = before_mulInv[1]
            ^ before_mulInv[4]
            ^ before_mulInv[6];
endfunction

function logic [7:0] mulGf28Inv;
  input [7:0] invInput;
  logic [7:0] after_imp;
  logic [3:0] imp_msb;
  logic [3:0] imp_lsb;
  logic [3:0] square;
  logic [3:0] xLamda;
  logic [3:0] lsb_xor_msb;
  logic [3:0] lsb_mulGf24;
  logic [3:0] xor_branch;
  logic [3:0] inv_branch;
  logic [7:0] imp_inv_in;
  //---------------------------------
  //Isomorphic mapping
  //---------------------------------
  after_imp[7] =   invInput[7]
                 ^ invInput[5];
                 
  after_imp[6] =   invInput[7]
                 ^ invInput[6]
                 ^ invInput[4]
                 ^ invInput[3]
                 ^ invInput[2]
                 ^ invInput[1];
  
  after_imp[5] =   invInput[7]
                 ^ invInput[5]
                 ^ invInput[3]
                 ^ invInput[2];
  
  after_imp[4] =   invInput[7]
                 ^ invInput[5]
                 ^ invInput[3]
                 ^ invInput[2]
                 ^ invInput[1];
  
  after_imp[3] =   invInput[7]
                 ^ invInput[6]
                 ^ invInput[2]
                 ^ invInput[1];
  
  after_imp[2] =   invInput[7]
                 ^ invInput[4]
                 ^ invInput[3]
                 ^ invInput[2]
                 ^ invInput[1];
  
  after_imp[1] =   invInput[6]
                 ^ invInput[4]
                 ^ invInput[1];
  
  after_imp[0] =   invInput[6]
                 ^ invInput[1]
                 ^ invInput[0];
  
  imp_msb[3:0] = after_imp[7:4];
  imp_lsb[3:0] = after_imp[3:0];
  //---------------------------------
  //MSB branch calculation
  //---------------------------------
  //Square
  square[3] = imp_msb[3];
  square[2] = imp_msb[3] ^ imp_msb[2];
  square[1] = imp_msb[2] ^ imp_msb[1];
  square[0] = imp_msb[3] ^ imp_msb[1] ^ imp_msb[0];
  //x Lambda
  xLamda[3] = square[2] ^ square[0];
  xLamda[2] = ^square[3:0];
  xLamda[1] = square[3];
  xLamda[0] = square[2];
  //---------------------------------
  //LSB branch calculation
  //---------------------------------
  //XOR with MSB
  lsb_xor_msb[3:0] = imp_msb[3:0] ^ imp_lsb[3:0];
  //Multiplication
  lsb_mulGf24[3:0] = mulGf24(lsb_xor_msb, imp_lsb);
  //---------------------------------
  //XOR MSB branch and LAB branch
  //---------------------------------
  xor_branch[3:0] = xLamda[3:0] ^ lsb_mulGf24[3:0];
  //---------------------------------
  //Multiplication inverse in GF(2^4)
  //---------------------------------
  case (xor_branch[3:0])
    4'h0: inv_branch[3:0] = 4'h0;
    4'h1: inv_branch[3:0] = 4'h1;
    4'h2: inv_branch[3:0] = 4'h3;
    4'h3: inv_branch[3:0] = 4'h2;
    4'h4: inv_branch[3:0] = 4'hF;
    4'h5: inv_branch[3:0] = 4'hC;
    4'h6: inv_branch[3:0] = 4'h9;
    4'h7: inv_branch[3:0] = 4'hB;
    4'h8: inv_branch[3:0] = 4'hA;
    4'h9: inv_branch[3:0] = 4'h6;
    4'ha: inv_branch[3:0] = 4'h8;
    4'hb: inv_branch[3:0] = 4'h7;
    4'hc: inv_branch[3:0] = 4'h5;
    4'hd: inv_branch[3:0] = 4'hE;
    4'he: inv_branch[3:0] = 4'hD;
    4'hf: inv_branch[3:0] = 4'h4;
    default: inv_branch[3:0] = 4'hx;
  endcase
  //---------------------------------
  //Final multiplication
  //---------------------------------
  imp_inv_in[7:4] = mulGf24(after_imp[7:4], inv_branch[3:0]);
  imp_inv_in[3:0] = mulGf24(lsb_xor_msb[3:0], inv_branch[3:0]);
  //---------------------------------
  //Isomorphic inverse
  //---------------------------------
  mulGf28Inv[7] = imp_inv_in[7]
            ^ imp_inv_in[6]
            ^ imp_inv_in[5]
            ^ imp_inv_in[1];
                 
  mulGf28Inv[6] = imp_inv_in[6]
            ^ imp_inv_in[2];
  
  mulGf28Inv[5] = imp_inv_in[6]
            ^ imp_inv_in[5]
            ^ imp_inv_in[1];
  
  mulGf28Inv[4] = imp_inv_in[6]
            ^ imp_inv_in[5]
            ^ imp_inv_in[4]
            ^ imp_inv_in[2]
            ^ imp_inv_in[1];
  
  mulGf28Inv[3] = imp_inv_in[5]
            ^ imp_inv_in[4]
            ^ imp_inv_in[3]
            ^ imp_inv_in[2]
            ^ imp_inv_in[1];
  
  mulGf28Inv[2] = imp_inv_in[7]
            ^ imp_inv_in[4]
            ^ imp_inv_in[3]
            ^ imp_inv_in[2]
            ^ imp_inv_in[1];
  
  mulGf28Inv[1] = imp_inv_in[5]
            ^ imp_inv_in[4];
  
  mulGf28Inv[0] = imp_inv_in[6]
            ^ imp_inv_in[5]
            ^ imp_inv_in[4]
            ^ imp_inv_in[2]
            ^ imp_inv_in[0];
endfunction

function logic [7:0] aes128_sbox;
  input [7:0] sbox_in;
  input encrypt_en;
  //
  logic [7:0] mulInvResult;
  logic [7:0] affineInvResult;
  logic [7:0] before_mulInv;
  //Input
  affineInvResult[7:0] = affineInv(sbox_in[7:0]);
  before_mulInv = encrypt_en? sbox_in[7:0]
                : affineInvResult[7:0];
  //Multiplication inverse in GF(2^8)
  mulInvResult[7:0] = mulGf28Inv(before_mulInv[7:0]);
  //Output
  aes128_sbox[7:0] = encrypt_en? 
                     affine(mulInvResult[7:0])
                   : mulInvResult[7:0];
endfunction
  always	@ (posedge clk_sys, negedge rst_n) begin
  	if (~rst_n) cipher_counter	<= 4'd0;
  	else if (cipher_complete)
  		cipher_counter	<= 4'd0;
  	else if (cipher_en | rkey_en)
  		cipher_counter	<= cipher_counter + 1'b1;
  end
  assign cipher_complete = (cipher_counter == 4'b1010)? 1'b1: 1'b0;
  assign round_num[3:0]  = cipher_counter[3:0];
  //Cipher status
  always @ (posedge clk_sys, negedge rst_n) begin
  	if (~rst_n)
      cipher_ready	<= 1'b1;
  	else if (cipher_en)
  		cipher_ready	<= 1'b0;
  	else if (cipher_complete)
      cipher_ready	<= 1'b1;
  end
  assign rkey_en = ~cipher_ready;
  //-------------------------------------------------------------------
  //SubBytes - converts the previous data to the cipher tables's value
  //-------------------------------------------------------------------
  //generating the SubBytes selection signal
  assign subbytes_sel[127:120]	= cipherText_reg[127:120];
  assign subbytes_sel[119:112]	= cipherText_reg[95:88];
  assign subbytes_sel[111:104]	= cipherText_reg[63:56];
  assign subbytes_sel[103:96]	  = cipherText_reg[31:24];
  assign subbytes_sel[95:88]	  = cipherText_reg[119:112];
  assign subbytes_sel[87:80]	  = cipherText_reg[87:80];
  assign subbytes_sel[79:72]	  = cipherText_reg[55:48];
  assign subbytes_sel[71:64]	  = cipherText_reg[23:16];
  assign subbytes_sel[63:56]	  = cipherText_reg[111:104];
  assign subbytes_sel[55:48]	  = cipherText_reg[79:72];
  assign subbytes_sel[47:40]	  = cipherText_reg[47:40];
  assign subbytes_sel[39:32]	  = cipherText_reg[15:8];
  assign subbytes_sel[31:24]	  = cipherText_reg[103:96];
  assign subbytes_sel[23:16]	  = cipherText_reg[71:64];
  assign subbytes_sel[15:8]	    = cipherText_reg[39:32];
  assign subbytes_sel[7:0]	    = cipherText_reg[7:0];
  //------------------------------------------------------------------------
  // SubBytes - Sbox
  //------------------------------------------------------------------------
  assign after_subBytes[127:120] = aes128_sbox(subbytes_sel[127:120], 1'b1);
  assign after_subBytes[119:112] = aes128_sbox(subbytes_sel[119:112], 1'b1);
  assign after_subBytes[111:104] = aes128_sbox(subbytes_sel[111:104], 1'b1);
  assign after_subBytes[103:96]	 = aes128_sbox(subbytes_sel[103:96],  1'b1);
  assign after_subBytes[95:88]	 = aes128_sbox(subbytes_sel[95:88],   1'b1);
  assign after_subBytes[87:80]	 = aes128_sbox(subbytes_sel[87:80],   1'b1);
  assign after_subBytes[79:72]	 = aes128_sbox(subbytes_sel[79:72],   1'b1);
  assign after_subBytes[71:64]	 = aes128_sbox(subbytes_sel[71:64],   1'b1);
  assign after_subBytes[63:56]	 = aes128_sbox(subbytes_sel[63:56],   1'b1);
  assign after_subBytes[55:48]	 = aes128_sbox(subbytes_sel[55:48],   1'b1);
  assign after_subBytes[47:40]	 = aes128_sbox(subbytes_sel[47:40],   1'b1);
  assign after_subBytes[39:32]	 = aes128_sbox(subbytes_sel[39:32],   1'b1);
  assign after_subBytes[31:24]	 = aes128_sbox(subbytes_sel[31:24],   1'b1);
  assign after_subBytes[23:16]	 = aes128_sbox(subbytes_sel[23:16],   1'b1);
  assign after_subBytes[15:8]	   = aes128_sbox(subbytes_sel[15:8],    1'b1);
  assign after_subBytes[7:0]	   = aes128_sbox(subbytes_sel[7:0],     1'b1);
  //------------------------------------------------------------------------
  // ShiftRows - Actual is a rotate
  //------------------------------------------------------------------------
  always @ (*) begin
  	//Non-shift
  	after_shiftRows[127:120] = after_subBytes[127:120];
  	after_shiftRows[119:112] = after_subBytes[119:112];
  	after_shiftRows[111:104] = after_subBytes[111:104];
  	after_shiftRows[103:96]  = after_subBytes[103:96];
  	//left-shift: one byte
  	after_shiftRows[71:64] = after_subBytes[95:88];
  	after_shiftRows[95:88] = after_subBytes[87:80];
  	after_shiftRows[87:80] = after_subBytes[79:72];
  	after_shiftRows[79:72] = after_subBytes[71:64];
  	//left-shift: two bytes
  	after_shiftRows[47:40] = after_subBytes[63:56];
  	after_shiftRows[39:32] = after_subBytes[55:48];
  	after_shiftRows[63:56] = after_subBytes[47:40];
  	after_shiftRows[55:48] = after_subBytes[39:32];
  	//left-shift: three bytes
  	after_shiftRows[23:16] = after_subBytes[31:24];
  	after_shiftRows[15:8]  = after_subBytes[23:16];
  	after_shiftRows[7:0]   = after_subBytes[15:8];
  	after_shiftRows[31:24] = after_subBytes[7:0];
  end
  
  //----------------------------------------------------------------------------
  //MixColumns - the matrix multiplication a(x) = {03}x3 + {01}x2 + {01}x + {02}
  //----------------------------------------------------------------------------
  //----------------------------------------------------------------------------
  // Convert the bit stream to columns
  //----------------------------------------------------------------------------
  assign mixColumns_in[127:96]	= {after_shiftRows[127:120],
                                 after_shiftRows[95:88],
  				                       after_shiftRows[63:56],
                                 after_shiftRows[31:24]};
                                 
  assign mixColumns_in[95:64]	= {after_shiftRows[119:112],
                                 after_shiftRows[87:80],
  				                       after_shiftRows[55:48],
                                 after_shiftRows[23:16]};
                                 
  assign mixColumns_in[63:32]	= {after_shiftRows[111:104],
                                 after_shiftRows[79:72],
  				                       after_shiftRows[47:40],
                                 after_shiftRows[15:8]};
                                 
  assign mixColumns_in[31:0]	= {after_shiftRows[103:96],
                               after_shiftRows[71:64],
  				                     after_shiftRows[39:32],
                               after_shiftRows[7:0]};
  //----------------------------------------------------------------------------
  //The MixColumn function
  //----------------------------------------------------------------------------
  assign after_mixColumns[127:96] = mixcol(mixColumns_in[127:96]);
  assign after_mixColumns[95:64]	= mixcol(mixColumns_in[95:64]);
  assign after_mixColumns[63:32]	= mixcol(mixColumns_in[63:32]);
  assign after_mixColumns[31:0]	  = mixcol(mixColumns_in[31:0]);
  //----------------------------------------------------------------------------
  //AddRoundKey - Adding the round key into the mix-column data
  //----------------------------------------------------------------------------
  assign addRoundKey_in[127:0] = cipher_en? plain_text[127:0]:
                                 (cipher_complete? mixColumns_in[127:0]: after_mixColumns[127:0]);
  assign after_addRoundkey[127:0] = addRoundKey_in[127:0] ^ (cipher_en? cipher_key[127:0]: round_key[127:0]);
  //Cipher text register
  always	@ (posedge clk_sys) begin
  	if (cipher_en | rkey_en)
      cipherText_reg <= after_addRoundkey;
  end
  //----------------------------------------------------------------------------
  //The cipher_text result
  //----------------------------------------------------------------------------
  assign	cipher_text	= cipherText_reg;

endmodule
