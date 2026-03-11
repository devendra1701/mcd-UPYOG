package org.egov.filestore.validator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import org.egov.tracer.model.CustomException;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

@Component
public class FileContentValidator {
	
	private static final Set<String> MALICIOUS_PATTERNS = new HashSet<>();

	static {
	    MALICIOUS_PATTERNS.add("<script");
	    MALICIOUS_PATTERNS.add("<?php");
	    MALICIOUS_PATTERNS.add("<jsp:");
	    MALICIOUS_PATTERNS.add("<%");
	    MALICIOUS_PATTERNS.add("eval(");
	    MALICIOUS_PATTERNS.add("runtime.getruntime");
	    MALICIOUS_PATTERNS.add("processbuilder");
	    MALICIOUS_PATTERNS.add("cmd.exe");
	    MALICIOUS_PATTERNS.add("/bin/sh");
	}

    public void validateContent(MultipartFile file, String extension) {

        // Only validate text-based formats
        if(!isTextFormat(extension)){
            return;
        }

        try(BufferedReader reader =
                    new BufferedReader(
                            new InputStreamReader(
                                    file.getInputStream(),
                                    StandardCharsets.UTF_8))) {

            String line;
            int linesChecked = 0;

            while((line = reader.readLine()) != null && linesChecked < 200){

                String lower = line.toLowerCase();

                for(String pattern : MALICIOUS_PATTERNS){

                    if(lower.contains(pattern)){
                        throw new CustomException(
                                "INVALID_FILE_CONTENT",
                                "Malicious content detected in file"
                        );
                    }
                }

                linesChecked++;
            }

        } catch(IOException e){

            throw new CustomException(
                    "INVALID_FILE",
                    "Unable to validate file content"
            );
        }
    }

    private boolean isTextFormat(String extension){

        return extension.equals("txt")
                || extension.equals("csv")
                || extension.equals("dxf");
    }
}
