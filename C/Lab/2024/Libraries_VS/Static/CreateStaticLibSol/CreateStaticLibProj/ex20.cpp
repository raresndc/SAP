#include <string>
#include <iostream>
#include "./ex20.hpp"

namespace ism {
	string::string() {
		this->length = 0;
		this->ps = NULL;
	}

	string::string(const char* str) {
		this->length = strlen(str);
		this->ps = new char[this->length + 1];
		strcpy(this->ps, str);
	}

	string::~string() {
		if (this->ps) delete[] this->ps;
		this->length = 0;
		this->ps = NULL;
	}

	string::string(const string& strSrc) {
		this->length = strSrc.length;
		if (strSrc.ps) {
			this->ps = new char[this->length + 1];
			strcpy(this->ps, strSrc.ps);
		}
		else this->ps = NULL;
	}

	const string& string::operator=(const string& strSrc) {
		if (this != &strSrc) {
			this->length = strSrc.length;
			if (this->ps) delete[] this->ps;
			this->ps = new char[this->length + 1];
			strcpy(this->ps, strSrc.ps);
		}
		return *this;
	}

	int string::getLength() {
		return this->length;
	}

	const string& string::operator+=(const string& strSrc) {
		char* ptemp = this->ps;
		this->length += strSrc.length;
		this->ps = new char[this->length + 1];
		strcpy(this->ps, ptemp);
		strcat(this->ps, strSrc.ps);
		if (ptemp) delete[] ptemp;

		return *this;
	}

	const string& string::operator+(const string& strSrc) {
		string* tempS;
		tempS = new string();
		tempS->length = this->length + strSrc.length;
		if (tempS->ps != NULL) delete[] tempS->ps;
		tempS->ps = new char[tempS->length + 1];
		strcpy(tempS->ps, this->ps);
		strcat(tempS->ps, strSrc.ps);
		return (*tempS);
	}

	const string& string::operator+(const char* str) {
		string* tempS;
		tempS = new string();
		tempS->length = this->length + (int)strlen(str);
		if (tempS->ps != NULL) delete[] tempS->ps;
		tempS->ps = new char[tempS->length + 1];
		strcpy(tempS->ps, this->ps);
		strcat(tempS->ps, str);
		return (*tempS);
	}


	//overloading unary operators 
	bool string::operator!() const {
		return (this->length == 0);
	}

	char& string::operator[](int pos) {
		if (pos >= 0 && pos < this->length) return this->ps[pos];
		else return this->ps[0];
	}

	const char& string::operator[](int pos) const {
		if (pos >= 0 && pos < this->length) return this->ps[pos];
		else return this->ps[0];
	}

	//overloading binary operators 
	bool string::operator==(const string& s2) const { // test identity of two objects (strings)
		return strcmp(this->ps, s2.ps) == 0;
	}

	bool string::operator!=(const string& s2) const { // test difference between two objects (strings) 
		return !(*this == s2);
		//return strcmp(this->ps, s2.ps) != 0;
	}

	bool string::operator<(const string& s2) const {
		return strcmp(this->ps, s2.ps) < 0;
	}

	bool string::operator>(const string& s2) const {
		return !(s2 < *this);
		//return strcmp(this->ps, s2.ps) > 0;
	}

	bool string::operator<=(const string& s2) const {
		return !(s2 < *this);
	}

	bool string::operator>=(const string& s2) const {
		return !(*this < s2);
	}

	ostream& operator<<(ostream& out, ism::string& S) {
		out << S.ps;
		return out;
	}

	istream& operator>>(istream& input, ism::string& S) {
		char temp[100];
		//input>>temp; // blanks are not considered
		input.getline(temp, sizeof(temp));

		//S=temp; <=> string tempObj(temp); S.operator =(tempObj);
		string tempObj(temp);
		S.operator =(tempObj);
		return input;
	}

	const ism::string& operator+(const char* op1, const ism::string& op2) {
		ism::string* tempS;
		tempS = new string();
		tempS->length = op2.length + (int)strlen(op1);
		if (tempS->ps != NULL) delete[] tempS->ps;
		tempS->ps = new char[tempS->length + 1];
		strcpy(tempS->ps, op1);
		strcat(tempS->ps, op2.ps);
		return (*tempS);
	}
}//end namespace