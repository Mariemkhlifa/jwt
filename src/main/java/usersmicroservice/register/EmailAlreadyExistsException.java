package usersmicroservice.register;

import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.http.HttpStatus;


@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class EmailAlreadyExistsException extends RuntimeException {
	private String message;
	
	public EmailAlreadyExistsException(String message)
	{
		super(message);
	}

}
