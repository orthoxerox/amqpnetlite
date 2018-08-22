//  ------------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation
//  All rights reserved. 
//  
//  Licensed under the Apache License, Version 2.0 (the ""License""); you may not use this 
//  file except in compliance with the License. You may obtain a copy of the License at 
//  http://www.apache.org/licenses/LICENSE-2.0  
//  
//  THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
//  EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR 
//  CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR 
//  NON-INFRINGEMENT. 
// 
//  See the Apache Version 2.0 License for specific language governing permissions and 
//  limitations under the License.
//  ------------------------------------------------------------------------------------

namespace Amqp.Sasl
{
    using System;
    using System.Text;
    using Amqp.Types;
    using System.Security.Cryptography;

    #pragma warning disable CS1591
    public sealed class SaslCramMD5Profile : SaslProfile
    {
        readonly string user;
        readonly string password;
        bool done = false;
        
        public SaslCramMD5Profile(string user, string password)
            : base(CramMD5Name)
        {
            this.user = user;
            this.password = password;
        }

        protected override ITransport UpgradeTransport(ITransport transport)
        {
            return transport;
        }

        protected override DescribedList GetStartCommand(string hostname)
        {
            return new SaslInit()
            {
                Mechanism = this.Mechanism
            };
        }

        protected override DescribedList OnCommand(DescribedList command)
        {
            if (!done) {
                byte[] b1 = Encoding.UTF8.GetBytes(this.user);
                byte[] b2 = Encoding.UTF8.GetBytes(this.password);

                var challenge = (SaslChallenge)command;

                using (var hmac = new HMACMD5(b2)) {
                    byte[] hash = hmac.ComputeHash(challenge.Challenge);
                    b2 = Encoding.UTF8.GetBytes(BitConverter.ToString(hash).ToLowerInvariant().Replace("-",""));
                }

                byte[] message = new byte[1 + b1.Length + b2.Length];
                Array.Copy(b1, 0, message, 0, b1.Length);
                message[b1.Length] = (byte)' ';
                Array.Copy(b2, 0, message, b1.Length + 1, b2.Length);

                SaslResponse response = new SaslResponse()
                {
                    Response = message
                };
                
                done = true;

                return response;
            } else {
                return null;
            }
        }
    }
}