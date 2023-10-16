import {
	alphabet as osloAlphabet,
	generateRandomString as osloGenerateRandomString
} from "oslo/random";

export const generateRandomString = (
	length: number,
	alphabet: string = osloAlphabet("0-9", "a-z")
) => {
	return osloGenerateRandomString(length, alphabet);
};
