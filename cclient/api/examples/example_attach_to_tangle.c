/*
 * Copyright (c) 2019 IOTA Stiftung
 * https://github.com/iotaledger/iota.c
 *
 * Refer to the LICENSE file for licensing information
 */

#include "cclient/api/examples/cclient_examples.h"

static tryte_t const *const TRUNK_HASH =
    (tryte_t *)"RVORZ9SIIP9RCYMREUIXXVPQIPHVCNPQ9HZWYKFWYWZRE9JQKG9REPKIASHUUECPSQO9JT9XNMVKWYGVA";
static tryte_t const *const BRANCH_HASH =
    (tryte_t *)"99999999IP9RCYMREUIXXVPQIPHVCNPQ9HZWYKFWYWZRE9JQKG9REPKIASHUUECPSQO9JT9XNMVKWYGVA";

static tryte_t const *const TX_HASH = (tryte_t*) "BYSWEAUTWXHXZ9YBZISEK9LUHWGMHXCGEVNZHRLUWQFCUSDXZHOFHWHL9MQPVJXXZLIXPX"
  "PXF9KYEREFSKCPKYIIKPZVLHUTDFQKKVVBBN9ATTLPCNPJDWDEVIYYLGPZGCWXOBDXMLJC9V"
  "O9QXTTBLAXTTBFUAROYEGQIVB9MJWJKXJMCUPTWAUGFZBTZCSJVRBGMYXTVBDDS9MYUJCPZ9"
  "YDWWQNIPUAIJXXSNLKUBSCOIJPCLEFPOXFJREXQCUVUMKSDOVQGGHRNILCO9GNCLWFM9APMN"
  "MWYASHXQAYBEXF9QRIHIBHYEJOYHRQJAOKAQ9AJJFQ9WEIWIJOTZATIBOXQLBMIJU9PCGBLV"
  "DDVFP9CFFSXTDUXMEGOOFXWRTLFGV9XXMYWEMGQEEEDBTIJ9OJOXFAPFQXCDAXOUDMLVYRMR"
  "LUDBETOLRJQAEDDLNVIRQJUBZBO9CCFDHIX9MSQCWYAXJVWHCUPTRSXJDESISQPRKZAFKFRU"
  "LCGVRSBLVFOPEYLEE99JD9SEBALQINPDAZHFAB9RNBH9AZWIJOTLBZVIEJIAYGMC9AZGNFWG"
  "RSWAXTYSXVROVNKCOQQIWGPNQZKHUNODGYADPYLZZZUQRTJRTODOUKAOITNOMWNGHJBBA99Q"
  "UMBHRENGBHTH9KHUAOXBVIVDVYYZMSEYSJWIOGGXZVRGN999EEGQMCOYVJQRIRROMPCQBLDY"
  "IGQO9AMORPYFSSUGACOJXGAQSPDY9YWRRPESNXXBDQ9OZOXVIOMLGTSWAMKMTDRSPGJKGBXQ"
  "IVNRJRFRYEZ9VJDLHIKPSKMYC9YEGHFDS9SGVDHRIXBEMLFIINOHVPXIFAZCJKBHVMQZEVWC"
  "OSNWQRDYWVAIBLSCBGESJUIBWZECPUCAYAWMTQKRMCHONIPKJYYTEGZCJYCT9ABRWTJLRQXK"
  "MWY9GWZMHYZNWPXULNZAPVQLPMYQZCYNEPOCGOHBJUZLZDPIXVHLDMQYJUUBEDXXPXFLNRGI"
  "PWBRNQQZJSGSJTTYHIGGFAWJVXWL9THTPWOOHTNQWCNYOYZXALHAZXVMIZE9WMQUDCHDJMIB"
  "WKTYH9AC9AFOT9DPCADCV9ZWUTE9QNOMSZPTZDJLJZCJGHXUNBJFUBJWQUEZDMHXGBPTNSPZ"
  "BR9TGSKVOHMOQSWPGFLSWNESFKSAZY9HHERAXALZCABFYPOVLAHMIHVDBGKUMDXC9WHHTIRY"
  "HZVWNXSVQUWCR9M9RAGMFEZZKZ9XEOQGOSLFQCHHOKLDSA9QCMDGCGMRYJZLBVIFOLBIJPRO"
  "KMHOYTBTJIWUZWJMCTKCJKKTR9LCVYPVJI9AHGI9JOWMIWZAGMLDFJA9WU9QAMEFGABIBEZN"
  "NAL9OXSBFLOEHKDGHWFQSHMPLYFCNXAAZYJLMQDEYRGL9QKCEUEJ9LLVUOINVSZZQHCIKPAG"
  "MT9CAYIIMTTBCPKWTYHOJIIY9GYNPAJNUJ9BKYYXSV9JSPEXYMCFAIKTGNRSQGUNIYZCRT9F"
  "OWENSZQPD9ALUPYYAVICHVYELYFPUYDTWUSWNIYFXPX9MICCCOOZIWRNJIDALWGWRATGLJXN"
  "AYTNIZWQ9YTVDBOFZRKO9CFWRPAQQRXTPACOWCPRLYRYSJARRKSQPR9TCFXDVIXLP9XVL99E"
  "RRDSOHBFJDJQQGGGCZNDQ9NYCTQJWVZIAELCRBJJFDMCNZU9FIZRPGNURTXOCDSQGXTQHKHU"
  "ECGWFUUYS9J9NYQ9U9P9UUP9YMZHWWWCIASCFLCMSKTELZWUGCDE9YOKVOVKTAYPHDF9ZCCQ"
  "AYPJIJNGSHUIHHCOSSOOBUDOKE9CJZGYSSGNCQJVBEFTZFJ9SQUHOASKRRGBSHWKBCBWBTJH"
  "OGQ9WOMQFHWJVEG9NYX9KWBTCAIXNXHEBDIOFO9ALYMFGRICLCKKLG9FOBOX9PDWNQRGHBKH"
  "GKKRLWTBEQMCWQRLHAVYYZDIIPKVQTHYTWQMTOACXZOQCDTJTBAAUWXSGJF9PNQIJ9AJRUMU"
  "VCPWYVYVARKR9RKGOUHHNKNVGGPDDLGKPQNOYHNKAVVKCXWXOQPZNSLATUJT9AUWRMPPSWHS"
  "TTYDFAQDXOCYTZHOYYGAIM9CELMZ9AZPWB9MJXGHOKDNNSZVUDAGXTJJSSZCPZVPZBYNNTUQ"
  "ABSXQWZCHDQSLGK9UOHCFKBIBNETK9999999999999999999999999999999999999999999"
  "99999999999999999999999999999999999999NOXDXXKUDWLOFJLIPQIBRBMGDYCPGDNLQO"
  "LQS99EQYKBIU9VHCJVIPFUYCQDNY9APGEVYLCENJIOBLWNB999999999XKBRHUD99C999999"
  "99NKZKEKWLDKMJCI9N9XQOLWEPAYWSH9999999999999999999999999KDDTGZLIPBNZKMLT"
  "OLOXQVNGLASESDQVPTXALEKRMIOHQLUHD9ELQDBQETS9QFGTYOYWLNTSKKMVJAUXSIROUICD"
  "OXKSYZTDPEDKOQENTJOWJONDEWROCEJIEWFWLUAACVSJFTMCHHXJBJRKAAPUDXXVXFWP9X99"
  "99IROUICDOXKSYZTDPEDKOQENTJOWJONDEWROCEJIEWFWLUAACVSJFTMCHHXJBJRKAAPUDXX"
  "VXFWP9X9999";

void example_attach_to_tangle(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  retcode_t ret = RC_OK;
  attach_to_tangle_req_t *attach_req = attach_to_tangle_req_new();
  attach_to_tangle_res_t *attach_res = attach_to_tangle_res_new();
  if (!attach_req || !attach_res) {
    printf("Error: OOM\n");
    goto done;
  }

  flex_trit_t raw_trits[FLEX_TRIT_SIZE_8019];

  attach_req->mwm = IOTA_CONFIG_NODE_MWM;

  // flex_trit and tryte convertion
  if (flex_trits_from_trytes(attach_req->trunk, NUM_TRITS_HASH, TRUNK_HASH, NUM_TRYTES_HASH, NUM_TRYTES_HASH) == 0) {
    printf("Error: converting trunk hash failed.\n");
    goto done;
  }

  if (flex_trits_from_trytes(attach_req->branch, NUM_TRITS_HASH, BRANCH_HASH, NUM_TRYTES_HASH, NUM_TRYTES_HASH) == 0) {
    printf("Error: converting branch hash failed.\n");
    goto done;
  }

  if (flex_trits_from_trytes(raw_trits, NUM_TRITS_SERIALIZED_TRANSACTION, TX_HASH, NUM_TRYTES_SERIALIZED_TRANSACTION,
                             NUM_TRYTES_SERIALIZED_TRANSACTION) == 0) {
    printf("Error: converting transaction hash failed.\n");
    goto done;
  }

  if ((ret = attach_to_tangle_req_trytes_add(attach_req, raw_trits)) != RC_OK) {
    printf("Adding trytes error: %s\n", error_2_string(ret));
    goto done;
  }

  if ((ret = iota_client_attach_to_tangle(s, attach_req, attach_res)) == RC_OK) {
    flex_trit_t *array_elt = NULL;
    HASH_ARRAY_FOREACH(attach_res->trytes, array_elt) {
      flex_trit_print(array_elt, NUM_TRITS_SERIALIZED_TRANSACTION);
      printf("\n");
    }
  } else {
    printf("API Error: %s\n", error_2_string(ret));
  }

done:
  attach_to_tangle_res_free(&attach_res);
  attach_to_tangle_req_free(&attach_req);
}