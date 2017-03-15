public class ACL {
	String router;// by default we have only one router
	String routerInterface;// by default we have only one port in this
							// assignment
	TrafficDirection direction;// direction of traffic on the port to be
								// controlled
	int order;// order based on bind, 1st sort field to execute
	int ACNumber;
	permissions permitstat;
	String src;
	String srcMask;
	String Des;
	String DesMask;
	protocols Protocol;
	String ordercode;// line in file
	int linenumber;// second sort field to execute
	ACLtype acLtype;// standard or extended
	String Description;
	int port;

	public ACL() {
		this.order = 0;
		this.port = -1;
		this.router = "R0";
		this.routerInterface = "E0";
		this.direction = TrafficDirection.IN;

	}

	public int getOrder() {
		return order;
	}
}
