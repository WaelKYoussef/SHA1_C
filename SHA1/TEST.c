//
//  TEST.c
//  SHA1
//
//  Created by Wael Youssef on 13/05/2023.
//  Copyright © 2023 DigitalEgypt. All rights reserved.
//

#include "TEST.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "SHA1.h"
#include "SHA1Org.h"

void digestTest(void) {
    // TODO: Replace this with a path to the test messages folder
    char messagesFolder[] = "<Path to 'Messages' folder>";
    char fileNames[100][100];
    int filesCount = 7;
    
    for (int ii = 1; ii <= filesCount; ii++) {
        sprintf(fileNames[ii - 1], "%sMsg%d.txt", messagesFolder, ii);
    }
    for (int ii = 1; ii <= filesCount; ii++) {
        printf("\n");
        
        char * fileContent = readFileContent(fileNames[ii - 1]);
        
        char output[1024];
        memset(output, 0, 1024);
        char* res = sha1KeyFromData((uint8_t *)fileContent, (uint32_t)strlen(fileContent));
        
        SHA1Context cx;
        SHA1Reset(&cx);
        SHA1Input(&cx, (uint8_t *)fileContent, (int)strlen(fileContent));
        SHA1Result(&cx, (uint8_t *)output);
        sprintf(output, "%x%x%x%x%x",
                cx.Intermediate_Hash[0],
                cx.Intermediate_Hash[1],
                cx.Intermediate_Hash[2],
                cx.Intermediate_Hash[3],
                cx.Intermediate_Hash[4]);
        
        
        int result = strcmp(res, output);
        printf("\nTestCase # %d %s!", ii, (result == 0 ? "Successful" : "Failed") );
        printf("\nMy Implementation:       %s\nOriginal Implementation: %s\n", res, output);

        free(fileContent);
        free(res);
    }
}

char * readFileContent(char * filePath) {
    char * buffer = 0;
    long length;
    FILE * f = fopen (filePath, "rb");

    if (f)
    {
      fseek (f, 0, SEEK_END);
      length = ftell (f);
      fseek (f, 0, SEEK_SET);
      buffer = malloc (length);
      if (buffer)
      {
        fread (buffer, 1, length, f);
      }
      fclose (f);
    }
    
    return buffer;
}
