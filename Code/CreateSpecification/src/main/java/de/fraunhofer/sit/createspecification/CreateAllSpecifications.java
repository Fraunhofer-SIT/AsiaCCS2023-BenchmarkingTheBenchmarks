package de.fraunhofer.sit.createspecification;

import java.io.File;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class CreateAllSpecifications {
	public static void main(String[] args) throws Exception {
		DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
		Document doc = docBuilder.newDocument();
		
		Element models = doc.createElement("Models");
		
		new CreateSpecificationsAppOWASP().generateModels(docBuilder, models);
		new CreateSpecificationsAppJuliet().generateModels(docBuilder, models);
		
		TransformerFactory transFactory = TransformerFactory.newInstance();
		Transformer transformer = transFactory.newTransformer();
		
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
		doc.appendChild(models);
		DOMSource source = new DOMSource(doc);

		File xmlFile = new File("../Output/Models.xml");
		StreamResult target = new StreamResult(xmlFile);

		transformer.transform(source, target);
	}
}
