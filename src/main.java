// This code is written by Mohammad Etemad for assignment two adv Network Security 2017. 
// anyone has the permission to use this code to learn more about acl commands.
// this is not a complete implementation of a router simulator and the focus is only
// on simulation of one interface in one router. some extra code about the selecting 
// interface is written but just to show the concept that there is more things to be aware of.

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Collections;
import java.util.Random;

public class main {

	public static List<packet> IncommingPackets = new ArrayList<packet>();
	public static String PacketsFile = "";
	public static String ACLsFile = "";
	public static String outputfilename = "";
	public static String outputfilenamedet = "";
	public static String router = "";
	public static String routerinterface = "";

	public static void interoduction() {
		System.out.println("Assignment two, Adv Network Security");
		System.out.println("------------------------------------");
		System.out.println("Please follow this format:");
		System.out.println("Command [packets file] [ACLs file] [output file] [active router] [active port]");
		System.out.println("defaults:");
		System.out.println(" [packets file]=/src/packets");
		System.out.println(" [ACLs file]=/src/ACLfile ");
		System.out.println(" [output file]=/src/results");
		System.out.println(" [active router]=R0");
		System.out.println(" [active port]=E0");
		System.out.println(" Traffic direction is IN by default.");

	}

	public static void main(String[] args) {

		interoduction();
		//show some help and info about program.
		loadDefaults(args);
		// load Defaults

		List<packet> packets = readPacketsFile(PacketsFile);
		// readPacketsFile function is gonna read packet file. the assignment
		// packet file has
		// only source and destination but for checking extended ACL commands I
		// need to have moreAdv Network Security
		// information about each packet such as source and destination port and
		// the protocol

		List<ACL> acls = readACLFile(ACLsFile);
		// readACLFile function is responsible for reading ACL commands
		// each command in files will be processed from top to button

		routerinterface = checkisrouterinterface(acls);

		acls = removeUnbindACLs(acls);
		// remove not binded ACLS, if there is no bind for an ACL command it
		// should not be processed
		// therefore I'm gonna remove the ACL commands dont bind to any
		// interface
		// we also remove all other ACL comands that is binded to other routers
		// or interface
		// we are going to select a specific interface on a specific port to
		// process its data.

		acls = sortACLCommands(acls);

		List<result> results = checkPakcetsbyACL(acls, packets);
		// process packets by acls

		showtheresults(results);
		// generate outputs
		// generate verbose output
		developresultdetails(results, outputfilenamedet);
		// generate assignment output
		developresult(results, outputfilename);
	}

	public static List<ACL> sortACLCommands(List<ACL> acls) {

		Collections.sort(acls, new Comparator<ACL>() {
			@Override
			public int compare(ACL acl1, ACL acl2) {
				if (acl1.order == acl2.order) {
					if (acl1.linenumber > acl2.linenumber) {
						return 1;
					} else {
						return -1;
					}
				} else {

					if (acl1.order > acl2.order) {
						return 1;
					} else {
						return -1;
					}
				}

			}
		});
		// I override compare function because the class ACl is defined in this
		// project and
		// if I dont define it the compare it will be consider as an object
		// therefore i can compare based on the order and linenumber
		return acls;

	}

	public static void loadDefaults(String[] args) {
		String CurrDir = System.getProperty("user.dir");
		PacketsFile = CurrDir + "/src/packets";
		ACLsFile = CurrDir + "/src/ACLfile";
		outputfilename = CurrDir + "/src/results";
		outputfilenamedet = CurrDir + "/src/resultsdet";

		try {
			router = args[4];
		} catch (Exception ex) {
			router = "R0";
		}

		try {
			routerinterface = args[5];
		} catch (Exception ex) {
			routerinterface = "E0";
		}

		switch (args.length) {
		case 0:
			break;
		case 1:
			PacketsFile = CurrDir + "/" + args[0];
			break;
		case 2:
			PacketsFile = CurrDir + "/" + args[0];
			ACLsFile = CurrDir + "/" + args[1];
			break;
		case 3:
			PacketsFile = CurrDir + "/" + args[0];
			ACLsFile = CurrDir + "/" + args[1];
			outputfilename = CurrDir + "/" + args[2];
			break;
		case 4:
			PacketsFile = CurrDir + "/" + args[0];
			ACLsFile = CurrDir + "/" + args[1];
			outputfilename = CurrDir + "/" + args[2];
			outputfilenamedet = CurrDir + "/" + args[3];
			break;

		}

	}

	public static void showtheresults(List<result> results) {
		// just to trace the results

		for (result res : results) {
			if (res.ACLCommand == null) {
				System.out.print(res.packet.Protocol + "|"
						+ res.packet.SourceIP + ":" + res.packet.SourcePort
						+ " -> " + res.packet.DestinationIP + ":"
						+ res.packet.DestinationPort + " "
						+ res.processResult.toString() + " : "
						+ res.Description + "\r\n");
			} else {
				System.out.print(res.packet.Protocol + "|"
						+ res.packet.SourceIP + ":" + res.packet.SourcePort
						+ " -> " + res.packet.DestinationPort + ":"
						+ res.packet.DestinationPort + " "
						+ res.processResult.toString() + " : " + " ACL#:"
						+ res.ACLCommand.Description + "\r\n");
			}
		}

	}

	public static void developresultdetails(List<result> results, String ofile) {
		try {

			File statText = new File(ofile);
			FileOutputStream is = new FileOutputStream(statText);
			OutputStreamWriter osw = new OutputStreamWriter(is);
			Writer w = new BufferedWriter(osw);

			System.out.print("Results:\r\n");
			for (result res : results) {

				if (res.ACLCommand == null) {
					w.write(res.packet.Protocol + "|" + res.packet.SourceIP
							+ ":" + res.packet.SourcePort + " -> "
							+ res.packet.DestinationIP + ":"
							+ res.packet.DestinationPort + " "
							+ res.processResult.toString() + " : "
							+ res.Description + "\r\n");
				} else {
					w.write(res.packet.Protocol + "|" + res.packet.SourceIP
							+ ":" + res.packet.SourcePort + " -> "
							+ res.packet.DestinationIP + ":"
							+ res.packet.DestinationPort + " "
							+ res.processResult.toString() + " : " + " ACL#:"
							+ res.ACLCommand.Description + "\r\n");
				}
			}

			w.close();
		} catch (IOException e) {
			System.err.println("There is a problem in writing on the file "
					+ ofile);
		}

	}

	public static void developresult(List<result> results, String ofile) {
		try {

			File statText = new File(ofile);
			FileOutputStream is = new FileOutputStream(statText);
			OutputStreamWriter osw = new OutputStreamWriter(is);
			Writer w = new BufferedWriter(osw);

			System.out.print("Results:\r\n");
			for (result res : results) {
				w.write(res.packet.SourceIP + " \t " + res.packet.DestinationIP
						+ "\t " + res.processResult.toString() + "\r\n");
				System.out.print(res.packet.SourceIP + " \t "
						+ res.packet.DestinationIP + "\t "
						+ res.processResult.toString() + "\r\n");

			}

			w.close();
		} catch (IOException e) {
			System.err.println("There is a problem in writing on the file "
					+ ofile);
		}

	}

	public static String checkisrouterinterface(List<ACL> acls) {
		String routerInterface = routerinterface;
		List<String> availablerouters = new ArrayList<String>();
		for (ACL acl : acls) {
			if (!acl.routerInterface.isEmpty()) {
				availablerouters.add(acl.routerInterface);

			}
		}
		boolean isinlist = false;
		for (String string : availablerouters) {
			if (string.equals(routerInterface)) {
				isinlist = true;
			}
		}
		if (!isinlist) {
			routerInterface = availablerouters.get(0);
		}

		return routerInterface;
	}

	public static List<ACL> removeUnbindACLs(List<ACL> acls) {

		List<ACL> results = new ArrayList<ACL>();
		for (ACL acl : acls) {
			if (acl.router == router & (acl.routerInterface == routerinterface)) {
				// there is binded router and interface
				results.add(acl);
			} else {
				// there is no router or interface binded. Therefore, the ACL
				// command will not be added
			}
		}
		return results;
	}

	public static boolean check(String ip, String mask, String chkip) {
		String[] ipparts = ip.split("\\.");
		String[] maskparts = mask.split("\\.");
		String[] chkipparts = chkip.split("\\.");
		// System.out.print(ip + " " + mask + " " + chkip + "\r\n");
		boolean result = false;
		for (int i = 0; i < 4; i++) {
			int res = 0;
			int p1 = Integer.valueOf(ipparts[i]);
			int p2 = Integer.valueOf(chkipparts[i]);
			int p3 = Integer.valueOf(maskparts[i]);
			res = (p1 ^ p2) | p3;
			// System.out.print(res + " ");
			if (res != Integer.parseInt(maskparts[i])) {
				result = true;
				break;
			}

		}
		// System.out.print("\r\n");
		return !result;

	}

	public static boolean checkpacketbyacl(ACL vclcmd, packet pkt) {
		// System.out.print("Check Source IP:\r\n");
		if (vclcmd.acLtype == ACLtype.StandardACL) {
			return check(vclcmd.src, vclcmd.srcMask, pkt.SourceIP);// is pkt in
		}
		if (vclcmd.acLtype == ACLtype.ExtendedACL) {
			boolean ch1 = check(vclcmd.src, vclcmd.srcMask, pkt.SourceIP);// is
																			// pkt
			// System.out.print("src is in range:" + ch1 + "\r\n"); // in
			// src
			boolean ch2 = check(vclcmd.Des, vclcmd.DesMask, pkt.DestinationIP);// is
																				// pkt
			// System.out.print("dest is in range:" + ch2 + "\r\n"); // in
			// desc
			boolean ch3 = (vclcmd.Protocol == pkt.Protocol);// check porotocol
			// System.out.print("porotocol same:" + ch3 + " " + vclcmd.Protocol
			// + " " + pkt.Protocol + " " + vclcmd.Description + "\r\n");
			if (vclcmd.Protocol == protocols.IP) {
				// System.out.print("the IP protocol means any protocol\r\n");
				ch3 = true;
			}
			boolean ch4 = true;
			if (vclcmd.port >= 0) {
				ch4 = (vclcmd.port == pkt.DestinationPort);// check porotocol
				// System.out.print("dest port is in range:" + ch4 + " "
				// + vclcmd.port + "\r\n");
			}
			return ch1 & ch2 & ch3 & ch4;

		}

		return false;

	}

	public static List<result> checkPakcetsbyACL(List<ACL> acls,
			List<packet> packets) {
		List<result> reslist = new ArrayList<result>();
		for (packet checkingpacket : packets) {
			System.out.print("Checking packet from " + checkingpacket.SourceIP
					+ " to " + checkingpacket.DestinationIP + " with "
					+ checkingpacket.Protocol + " protocol... \r\n");
			result res = new result();
			if (acls.size() == 0) {
				res.packet = checkingpacket;
				res.Description = "no ACL command is binded to the interface.";
				res.processResult = ProcessResult.permitted;
				reslist.add(res);
				continue;
			} else {
				res.packet = checkingpacket;
				boolean rsch = false;
				for (ACL ACLCommand : acls) {

					rsch = checkpacketbyacl(ACLCommand, checkingpacket);
					// System.out.print("ACL:"+ACLCommand.Description+rsch+"\r\n");
					// checkAcls=checkAcls|rsch;
					if (rsch) {
						res.ACLCommand = ACLCommand;
						break;
					}

				}
				if (!rsch) {
					res.Description = "no ACL command for this packet.";
					res.processResult = ProcessResult.denied;
					System.out.print("No ACL for this pkt=>  drop" + "\r\n");
				} else {
					if (res.ACLCommand.permitstat == permissions.permit) {
						res.processResult = ProcessResult.permitted;
						// System.out.print("ACL:" + res.ACLCommand.Description
						// + " Pass" + "\r\n");
					} else {
						res.processResult = ProcessResult.denied;
						// System.out.print("ACL:" + res.ACLCommand.Description
						// + " Drop" + "\r\n");
					}
				}

			}

			reslist.add(res);
		}
		return reslist;

	}

	public static List<ACL> readACLFile(String filename) {
		Path path = Paths.get(filename);
		List<ACL> acls = new ArrayList<ACL>();

		List<String> lines = null;
		try {
			lines = Files.readAllLines(path);
		} catch (IOException e) {
			System.out.print("error in reading file " + filename);
			e.printStackTrace();
		}

		String currentInterface = "E0";// default port
		System.out.print("reading ACL commands...\r\n");
		for (int i = 0; i < lines.size(); i++) {
			String temp = lines.get(i);
			System.out.print(temp + " \r\n");
			ACL command = new ACL();
			String[] items = temp.split(" ");
			command.linenumber = i;
			command.ordercode = temp;
			if (items.length > 0) {
				switch (items[0].toLowerCase()) {
				case "access-list":
					// 1-99 Standard ACL
					command.Description = temp;
					command.ACNumber = Integer.parseInt(items[1]);
					if ((command.ACNumber <= 99) & (command.ACNumber >= 1)) {// Standard
						if (items[2].equals("deny")) {
							command.permitstat = permissions.deny;
						}
						if (items[2].equals("permit")) {
							command.permitstat = permissions.permit;
						}
						command.acLtype = ACLtype.StandardACL;
						String s = items[3].toLowerCase();
						if (s.equals("any")) {
							command.src = "0.0.0.0";
							command.srcMask = "255.255.255.255";
						} else {

							command.src = items[3];
							command.srcMask = items[4];

						}
					}
					if ((command.ACNumber <= 199) & (command.ACNumber >= 100)) {
						// Extended ACL
						command.acLtype = ACLtype.ExtendedACL;
						if (items[2].equals("deny")) {
							command.permitstat = permissions.deny;
						}
						if (items[2].equals("permit")) {
							command.permitstat = permissions.permit;

						}

						switch (items[3].toUpperCase()) {
						case "IP":
							command.Protocol = protocols.IP;
							break;
						case "TCP":
							command.Protocol = protocols.TCP;
							break;
						case "UDP":
							command.Protocol = protocols.UDP;
							break;
						case "ICMP":
							command.Protocol = protocols.icmp;
							break;
						}
						String s = items[4].toLowerCase();
						if (s.equals("any")) {
							command.src = "0.0.0.0";
							command.srcMask = "255.255.255.255";
							if (items[5].toLowerCase().equals("any")) {
								command.Des = "0.0.0.0";
								command.DesMask = "255.255.255.255";
								if (items.length >= 8)
									command.port = Integer.parseInt(items[7]);
							} else {

								command.Des = items[5];
								command.DesMask = items[6];
								if (items.length >= 9)
									command.port = Integer.parseInt(items[8]);
							}
						} else {
							command.src = items[4];
							command.srcMask = items[5];
							if (items[6].toLowerCase().equals("any")) {
								command.Des = "0.0.0.0";
								command.DesMask = "255.255.255.255";
								if (items.length >= 9)
									command.port = Integer.parseInt(items[8]);
							} else {

								command.Des = items[6];
								command.DesMask = items[7];
								if (items.length >= 10)
									command.port = Integer.parseInt(items[9]);
							}
						}

					}
					// just to trace
					// System.out.print(command.ACNumber + " "
					// + command.src + " " + command.srcMask + " "
					// + command.permitstat.toString() + " "
					// + command.acLtype.toString() + " "
					// + command.Protocol + " \r\n");
					acls.add(command);
					break;
				case "interface":

					currentInterface = items[1];

					break;

				case "ip":
					// find last order
					int order = 0;
					for (ACL element : acls) {
						if (element.order > order) {
							order = element.order;
						}
					}
					order++;
					int ACLNumber = Integer.parseInt(items[2]);
					TrafficDirection Trafficdirection = null;
					String routerInterface = currentInterface;
					switch (items[3].toLowerCase()) {
					case "in":
						Trafficdirection = TrafficDirection.IN;
						break;
					case "out":
						Trafficdirection = TrafficDirection.OUT;
						break;
					}
					for (ACL element : acls) {
						if (element.ACNumber == ACLNumber) {
							element.router = "R1";
							element.routerInterface = routerInterface;
							element.direction = Trafficdirection;
							element.order = order;
						}
					}
					break;
				}
				command = null;
				System.gc();
			}
		}
		return acls;
	}

	public static List<packet> readPacketsFile(String filename) {
		List<packet> packets = new ArrayList<packet>();
		Path path = Paths.get(filename);
		List<String> lines = null;
		try {
			lines = Files.readAllLines(path);
		} catch (IOException e) {
			System.out.print("Error in reading file: " + filename);
			e.printStackTrace();
		}

		System.out.print(" Reading packets in file...\r\n");
		System.out
				.print(" X in IP and Port addresses will be replaced by random number in order to test the program easier.\r\n");
		System.out
				.print(" Packets without Protocol attribute are belong to IP protocol.\r\n");
		System.out
				.print(" Packets without Source and Destination Port will be assigned by a random port number.\r\n");
		System.out
				.print(" packet file data has been modified in order to process Extended ACL.\r\n");
		System.out
				.print(" Extended ACLs need these information to process each packet.\r\n");
		System.out
				.print(" to check the details take a look at detailed results.\r\n");
		for (String temp : lines) {
			Random rand = new Random();
			int n = rand.nextInt(250) + 1;
			int m = rand.nextInt(250) + 1;
			String np = Integer.toString(rand.nextInt(250) + 1);
			while (temp.indexOf("X") > 0) {

				np = Integer.toString(rand.nextInt(250) + 1);
				temp = temp.replaceFirst("X", np);

			}
			packet p1 = new packet();
			String[] items = temp.split("	");
			System.out.print(temp + "\r\n");

			switch (items.length) {
			case 2:
				p1.SourceIP = items[0];
				p1.DestinationIP = items[1];
				p1.Protocol = protocols.IP;

				n = rand.nextInt(250) + 1;
				m = rand.nextInt(250) + 1;
				p1.SourcePort = n;

				p1.DestinationPort = m;
				break;
			case 3:

				p1.SourceIP = items[0];
				p1.DestinationIP = items[1];
				switch (items[2].toUpperCase()) {
				case "IP":
					p1.Protocol = protocols.IP;
					break;
				case "TCP":
					p1.Protocol = protocols.TCP;
					break;
				case "UDP":
					p1.Protocol = protocols.UDP;
					break;
				case "ICMP":
					p1.Protocol = protocols.icmp;
					break;
				}

				n = rand.nextInt(250) + 1;
				m = rand.nextInt(250) + 1;
				p1.SourcePort = n;
				p1.DestinationPort = m;
				break;

			case 4:
				p1.SourceIP = items[0];
				p1.DestinationIP = items[1];
				// I use IP,TCP,UDP,ICMP protocol because in source[1] I see
				// only these items
				switch (items[2].toUpperCase()) {
				case "IP":
					p1.Protocol = protocols.IP;
					break;
				case "TCP":
					p1.Protocol = protocols.TCP;
					break;
				case "UDP":
					p1.Protocol = protocols.UDP;
					break;
				case "ICMP":
					p1.Protocol = protocols.icmp;
					break;
				}
				n = rand.nextInt(250) + 1;

				p1.SourcePort = n;
				p1.DestinationPort = Integer.parseInt(items[4]);
				break;
			case 5:
				p1.SourceIP = items[0];
				p1.DestinationIP = items[1];
				switch (items[2].toUpperCase()) {
				case "IP":
					p1.Protocol = protocols.IP;
					break;
				case "TCP":
					p1.Protocol = protocols.TCP;
					break;
				case "UDP":
					p1.Protocol = protocols.UDP;
					break;
				case "ICMP":
					p1.Protocol = protocols.icmp;
					break;
				}
				p1.SourcePort = Integer.parseInt(items[3]);
				p1.DestinationPort = Integer.parseInt(items[4]);
				break;
			}

			packets.add(p1);
			p1 = null;
			System.gc();
		}
		return packets;

	}

}

// [1] http://netcert.tripod.com/ccna/routers/accesscmd.html