/*
 * Copyright 2013, 2014 Megion Research & Development GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dbchain.client.java.secp256k1.address;

/**
 * base implementation of MD4 family style digest as outlined in
 * "Handbook of Applied Cryptography", pages 344 - 347.
 */
public abstract class GeneralDigest {
   private byte[] xBuf;
   private int xBufOff;

   private long byteCount;

   /**
    * Standard constructor
    */
   protected GeneralDigest() {
      xBuf = new byte[4];
      xBufOff = 0;
   }

   public void update(byte in) {
      xBuf[xBufOff++] = in;

      if (xBufOff == xBuf.length) {
         processWord(xBuf, 0);
         xBufOff = 0;
      }

      byteCount++;
   }

   public void update(byte[] in, int inOff, int len) {
      //
      // fill the current word
      //
      while ((xBufOff != 0) && (len > 0)) {
         update(in[inOff]);

         inOff++;
         len--;
      }

      //
      // process whole words.
      //
      while (len > xBuf.length) {
         processWord(in, inOff);

         inOff += xBuf.length;
         len -= xBuf.length;
         byteCount += xBuf.length;
      }

      //
      // load in the remainder.
      //
      while (len > 0) {
         update(in[inOff]);

         inOff++;
         len--;
      }
   }

   public void finish() {
      long bitLength = (byteCount << 3);

      //
      // add the pad bytes.
      //
      update((byte) 128);

      while (xBufOff != 0) {
         update((byte) 0);
      }

      processLength(bitLength);

      processBlock();
   }

   public void reset() {
      byteCount = 0;

      xBufOff = 0;
      for (int i = 0; i < xBuf.length; i++) {
         xBuf[i] = 0;
      }
   }

   protected abstract void processWord(byte[] in, int inOff);

   protected abstract void processLength(long bitLength);

   protected abstract void processBlock();
}
